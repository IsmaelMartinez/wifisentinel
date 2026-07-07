package io.github.ismaelmartinez.wifisentinel.store

import androidx.room.Database
import androidx.room.RoomDatabase

/**
 * Single-table Room database backing the on-device scan history. `exportSchema`
 * stays off — the schema is small and each change ships a hand-written
 * [MIGRATION_1_2]-style migration rather than a diffed schema JSON.
 *
 * v2 added the nullable `nearbyCount` column so the history list can mark a
 * nearby-only survey (see `store/Migrations.kt` and docs/android-companion.md §9).
 */
@Database(entities = [ScanEntity::class], version = 2, exportSchema = false)
abstract class ScanDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao
}
