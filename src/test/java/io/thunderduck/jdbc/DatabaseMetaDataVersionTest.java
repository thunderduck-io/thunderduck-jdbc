package io.thunderduck.jdbc;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class DatabaseMetaDataVersionTest {

    @Test
    void driverVersionMatchesTheDriver() {
        ThunderduckDatabaseMetaData md = new ThunderduckDatabaseMetaData(null, null, "jdbc:thunderduck://api.example/");
        ThunderduckDriver driver = new ThunderduckDriver();
        assertEquals(2, md.getDriverMinorVersion());
        assertEquals(driver.getMinorVersion(), md.getDriverMinorVersion());
        assertEquals(driver.getMajorVersion(), md.getDriverMajorVersion());
    }
}
