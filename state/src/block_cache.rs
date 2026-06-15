//! SQLite-backed compact block cache (the `compactblocks` table in BlockDb).

use std::ops::Range;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;
use prost::Message;
use rusqlite::{params, Connection, OptionalExtension};
use zcash_client_backend::{
    data_api::{
        chain::{error::Error as ChainError, BlockCache, BlockSource},
        scanning::ScanRange,
    },
    proto::compact_formats::CompactBlock,
};
use zcash_client_sqlite::{chain::init::init_cache_database, error::SqliteClientError, BlockDb};
use zcash_protocol::consensus::BlockHeight;

use crate::treasury::TreasuryError;

/// Persistent compact-block cache backed by the treasury `BlockDb` file.
pub struct PersistedBlockCache {
    conn: Mutex<Connection>,
}

impl PersistedBlockCache {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TreasuryError> {
        let db = BlockDb::for_path(&path)?;
        init_cache_database(&db).map_err(|e| TreasuryError::Init(e.to_string()))?;
        let conn = Connection::open(path.as_ref())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn with_conn<F, T>(&self, f: F) -> Result<T, SqliteClientError>
    where
        F: FnOnce(&Connection) -> Result<T, SqliteClientError>,
    {
        let conn = self.conn.lock().expect("block cache lock");
        f(&conn)
    }
}

fn range_bounds(range: &ScanRange) -> Range<u64> {
    u64::from(u32::from(range.block_range().start))..u64::from(u32::from(range.block_range().end))
}

fn block_source_err<WalletErrT, E: Into<SqliteClientError>>(
    err: E,
) -> ChainError<WalletErrT, SqliteClientError> {
    ChainError::BlockSource(err.into())
}

impl BlockSource for PersistedBlockCache {
    type Error = SqliteClientError;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
    {
        let conn = self.conn.lock().expect("block cache lock");
        let mut stmt = conn
            .prepare(
                "SELECT height, data FROM compactblocks
                 WHERE height >= ? ORDER BY height ASC LIMIT ?",
            )
            .map_err(|e| ChainError::BlockSource(e.into()))?;

        let mut rows = stmt
            .query(params![
                from_height.map_or(0u32, u32::from),
                limit
                    .and_then(|l| u32::try_from(l).ok())
                    .unwrap_or(u32::MAX)
            ])
            .map_err(|e| ChainError::BlockSource(e.into()))?;

        let mut from_height_found = from_height.is_none();
        while let Some(row) = rows
            .next()
            .map_err(|e| ChainError::BlockSource(e.into()))?
        {
            let height = BlockHeight::from_u32(
                row.get(0)
                    .map_err(|e| ChainError::BlockSource(e.into()))?,
            );
            if !from_height_found {
                let from = from_height.expect("set when not found");
                if from != height {
                    return Err(block_source_err::<WalletErrT, _>(SqliteClientError::CacheMiss(
                        from,
                    )));
                }
                from_height_found = true;
            }
            let data: Vec<u8> = row
                .get(1)
                .map_err(|e| ChainError::BlockSource(e.into()))?;
            let block = CompactBlock::decode(&data[..])
                .map_err(|e| ChainError::BlockSource(e.into()))?;
            if block.height() != height {
                return Err(block_source_err::<WalletErrT, _>(SqliteClientError::CorruptedData(
                    format!(
                    "block height {} != row {}",
                        block.height(),
                        height
                    ),
                )));
            }
            with_block(block)?;
        }

        if !from_height_found {
            let from = from_height.expect("set when not found");
            return Err(block_source_err::<WalletErrT, _>(SqliteClientError::CacheMiss(from)));
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for PersistedBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, SqliteClientError> {
        self.with_conn(|conn| {
            match range {
                Some(range) => {
                    let start = u32::from(range.block_range().start);
                    let end = u32::from(range.block_range().end);
                    let height: Option<u32> = conn
                        .query_row(
                            "SELECT MAX(height) FROM compactblocks WHERE height >= ?1 AND height < ?2",
                            params![start, end],
                            |row| row.get(0),
                        )
                        .optional()?
                        .flatten();
                    Ok(height.map(BlockHeight::from_u32))
                }
                None => {
                    let height: Option<u32> = conn
                        .query_row("SELECT MAX(height) FROM compactblocks", [], |row| row.get(0))
                        .optional()?
                        .flatten();
                    Ok(height.map(BlockHeight::from_u32))
                }
            }
        })
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, SqliteClientError> {
        let bounds = range_bounds(range);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT data FROM compactblocks
                 WHERE height >= ?1 AND height < ?2 ORDER BY height ASC",
            )?;
            let mut rows = stmt.query(params![bounds.start, bounds.end])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                let data: Vec<u8> = row.get(0)?;
                out.push(CompactBlock::decode(&data[..]).map_err(SqliteClientError::from)?);
            }
            Ok(out)
        })
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), SqliteClientError> {
        self.with_conn(|conn| {
            for block in compact_blocks {
                let data = block.encode_to_vec();
                conn.execute(
                    "INSERT OR REPLACE INTO compactblocks (height, data) VALUES (?1, ?2)",
                    params![u32::from(block.height()), data],
                )?;
            }
            Ok(())
        })
    }

    async fn delete(&self, range: ScanRange) -> Result<(), SqliteClientError> {
        let bounds = range_bounds(&range);
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM compactblocks WHERE height >= ?1 AND height < ?2",
                params![bounds.start, bounds.end],
            )?;
            Ok(())
        })
    }
}