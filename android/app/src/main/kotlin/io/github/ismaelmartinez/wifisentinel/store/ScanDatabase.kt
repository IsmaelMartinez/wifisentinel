package io.github.ismaelmartinez.wifisentinel.store

import androidx.room.Database
import androidx.room.RoomDatabase

/**
 * Single-table Room database backing the on-device scan history. `exportSchema`
 * is off because the schema is trivial and there are no migrations to diff yet;
 * turn it on and add a migration when the schema first changes.
 */
@Database(entities = [ScanEntity::class], version = 1, exportSchema = false)
abstract class ScanDatabase : RoomDatabase() {
    abstract fun scanDao(): ScanDao
}
