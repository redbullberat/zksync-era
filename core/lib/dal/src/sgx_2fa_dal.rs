use std::time::{Duration, Instant};

use sqlx::postgres::types::PgInterval;
use zksync_types::L1BatchNumber;

use crate::{
    instrument::InstrumentExt,
    time_utils::{duration_to_naive_time, pg_interval_from_duration},
    StorageProcessor,
};

#[derive(Debug)]
pub struct Sgx2faDal<'a, 'c> {
    pub(crate) storage: &'a mut StorageProcessor<'c>,
}

/// The amount of attempts to process a job before giving up.
pub const JOB_MAX_ATTEMPT: i16 = 10;

/// Time to wait for job to be processed
const JOB_PROCESSING_TIMEOUT: PgInterval = pg_interval_from_duration(Duration::from_secs(10 * 60));

/// Status of a job that the producer will work on.

#[derive(Debug, sqlx::Type)]
#[sqlx(type_name = "sgx_2fa_job_status")]
pub enum Sgx2faJobStatus {
    /// When the job is queued. Metadata calculator creates the job and marks it as queued.
    Queued,
    /// The job is not going to be processed. This state is designed for manual operations on DB.
    /// It is expected to be used if some jobs should be skipped like:
    /// - testing purposes (want to check a specific L1 Batch, I can mark everything before it skipped)
    /// - trim down costs on some environments (if I've done breaking changes,
    /// makes no sense to wait for everything to be processed, I can just skip them and save resources)
    ManuallySkipped,
    /// Currently being processed by one of the jobs. Transitory state, will transition to either
    /// [`Sgx2faStatus::Successful`] or [`Sgx2faStatus::Failed`].
    InProgress,
    /// The final (happy case) state we expect all jobs to end up. After the run is complete,
    /// the job uploaded it's inputs, it lands in successful.
    Successful,
    /// The job failed for reasons. It will be marked as such and the error persisted in DB.
    /// If it failed less than MAX_ATTEMPTs, the job will be retried,
    /// otherwise it will stay in this state as final state.
    Failed,
}

impl Sgx2faDal<'_, '_> {
    pub async fn create_sgx_2fa_job(&mut self, l1_batch_number: L1BatchNumber) -> sqlx::Result<()> {
        unimplemented!();
        /*
        sqlx::query!(
            r#"
            INSERT INTO
                sgx_2fa_jobs (l1_batch_number, status, created_at, updated_at)
            VALUES
                ($1, $2, NOW(), NOW())
            ON CONFLICT (l1_batch_number) DO NOTHING
            "#,
            l1_batch_number.0 as i64,
            Sgx2faStatus::Queued as Sgx2faJobStatus,
        )
        .instrument("create_sgx_2fa_job")
        .report_latency()
        .execute(self.storage)
        .await?;

        Ok(())
        */
    }

    pub async fn get_next_sgx_2fa_job(&mut self) -> sqlx::Result<Option<L1BatchNumber>> {
        /*
        let l1_batch_number = sqlx::query!(
        r#"
        UPDATE sgx_2fa_jobs
        SET
            status = $1,
            attempts = attempts + 1,
            updated_at = NOW(),
            processing_started_at = NOW()
        WHERE
            l1_batch_number = (
                SELECT
                    l1_batch_number
                FROM
                    sgx_2fa_jobs
                WHERE
                    status = $2
                    OR (
                        status = $1
                        AND processing_started_at < NOW() - $4::INTERVAL
                    )
                    OR (
                        status = $3
                        AND attempts < $5
                    )
                ORDER BY
                    l1_batch_number ASC
                LIMIT
                    1
                FOR UPDATE
                    SKIP LOCKED
            )
        RETURNING
            sgx_2fa_jobs.l1_batch_number
        "#,
            Sgx2faJobStatus::InProgress as Sgx2faJobStatus,
            Sgx2faJobStatus::Queued as Sgx2faJobStatus,
            Sgx2faJobStatus::Failed as Sgx2faJobStatus,
            &JOB_PROCESSING_TIMEOUT,
            JOB_MAX_ATTEMPT,
        )
        .instrument("get_next_sgx_2fa_job")
        .report_latency()
        .fetch_optional(self.storage)
        .await?
        .map(|job| L1BatchNumber(job.l1_batch_number as u32));
        */
        Ok(Some(L1BatchNumber(19)))
    }

    pub async fn get_sgx_2fa_job_attempts(
        &mut self,
        l1_batch_number: L1BatchNumber,
    ) -> sqlx::Result<Option<u32>> {
        unimplemented!();
        /*
        let attempts = sqlx::query!(
        r#"
        SELECT
            attempts
        FROM
            sgx_2fa_jobs
        WHERE
            l1_batch_number = $1
        "#,
            l1_batch_number.0 as i64,
        )
        .fetch_optional(self.storage.conn())
        .await?
        .map(|job| job.attempts as u32);

        Ok(attempts)
        */
    }

    pub async fn mark_job_as_successful(
        &mut self,
        l1_batch_number: L1BatchNumber,
        started_at: Instant,
        object_path: &str,
    ) -> sqlx::Result<()> {
        unimplemented!();
        /*
        sqlx::query!(
        r#"
        UPDATE sgx_2fa_jobs
        SET
            status = $1,
            updated_at = NOW(),
            time_taken = $3,
            input_blob_url = $4
        WHERE
            l1_batch_number = $2
        "#,
            Sgx2faJobStatus::Successful as Sgx2faJobStatus,
            l1_batch_number.0 as i64,
            duration_to_naive_time(started_at.elapsed()),
            object_path,
        )
        .instrument("mark_job_as_successful")
        .report_latency()
        .execute(self.storage)
        .await?;

        Ok(())
        */
    }

    pub async fn mark_job_as_failed(
        &mut self,
        l1_batch_number: L1BatchNumber,
        started_at: Instant,
        error: String,
    ) -> sqlx::Result<Option<u32>> {
        unimplemented!();
        /*
         let attempts = sqlx::query!(
        r#"
        UPDATE sgx_2fa_jobs
        SET
            status = $1,
            updated_at = NOW(),
            time_taken = $3,
            error = $4
        WHERE
            l1_batch_number = $2
            AND status != $5
        RETURNING
            sgx_2fa_jobs.attempts
        "#,
            Sgx2faJobStatus::Failed as Sgx2faJobStatus,
            l1_batch_number.0 as i64,
            duration_to_naive_time(started_at.elapsed()),
            error,
            Sgx2faJobStatus::Successful as Sgx2faJobStatus,
        )
        .instrument("mark_job_as_failed")
        .report_latency()
        .fetch_optional(self.storage)
        .await?
        .map(|job| job.attempts as u32);

        Ok(attempts)
        */
    }
}

/// These functions should only be used for tests.
impl Sgx2faDal<'_, '_> {
    pub async fn delete_all_jobs(&mut self) -> sqlx::Result<()> {
        unimplemented!();
        /*
        sqlx::query!(
        r#"
        DELETE FROM sgx_2fa_jobs
        "#,
        )
        .execute(self.storage.conn())
        .await?;
        Ok(())
        */
    }
}
