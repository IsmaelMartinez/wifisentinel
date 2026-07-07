package io.github.ismaelmartinez.wifisentinel.store

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * v1 → v2: add the nullable `nearbyCount` denormalised column. Existing rows
 * predate the column, so they get SQL NULL ("not collected") — exactly the
 * sentinel the summary treats as "no RF list recorded", so old history rows
 * keep rendering by SSID as before.
 */
internal val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE scans ADD COLUMN nearbyCount INTEGER")
    }
}
