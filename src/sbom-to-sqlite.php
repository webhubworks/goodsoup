<?php

function insertPackage($db, $package, $repositoryName, $ecosystem, $isDev): void
{
    $normalColumns = [
        'repository',
        'ecosystem',
        'asset',
        'name',
        'version',
        'bom_ref',
        'is_dev',
        'description',
        'author',
        'license',
    ];
    $manualColumns = ['manual_end_of_support', 'manual_risk_level'];
    $identifierColumns = ['ecosystem', 'bom_ref'];

    $itemData = [
        'repository' => $repositoryName,
        'ecosystem' => $ecosystem,
        'asset' => $package['type'] ?? '',
        'name' => $package['name'] ?? '',
        'version' => $package['version'] ?? '',
        'bom_ref' => $package['bom-ref'] ?? '',
        'is_dev' => $isDev ?? 0,
        'description' => $package['description'] ?? '',
        'author' => $package['author'] ?? '',
        'license' => transformLicensesString($package),
        'manual_end_of_support' => null,
        'manual_risk_level' => null,
    ];

    /**
     * Find an existing item based on non-manual columns
     */
    $whereClause = implode(' AND ', array_map(fn($col) => "$col = :$col", $identifierColumns));
    $query = "SELECT * FROM items WHERE $whereClause ORDER BY id DESC LIMIT 1";
    $stmt = $db->prepare($query);

    foreach ($identifierColumns as $col) {
        $stmt->bindValue(":$col", $itemData[$col]);
    }

    $stmt->execute();
    $existingItem = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingItem) {
        /**
         * Compare normal columns to see if there's a difference
         */
        $hasChanges = false;
        foreach ($normalColumns as $col) {
            // We cannot use !== here as we sometime compare different types
            if ($existingItem[$col] != $itemData[$col]) {
                $hasChanges = true;
                break;
            }
        }

        if ($hasChanges) {
            /**
             * Prepare data for new row with copied manual values
             */
            foreach ($manualColumns as $manualCol) {
                $itemData[$manualCol] = $existingItem[$manualCol];
            }

            /**
             * Insert the new item with updated data
             */
            $columns = implode(', ', array_keys($itemData));
            $placeholders = implode(', ', array_map(fn($col) => ":$col", array_keys($itemData)));
            $insertQuery = "INSERT INTO items ($columns) VALUES ($placeholders)";
            $insertStmt = $db->prepare($insertQuery);

            foreach ($itemData as $col => $value) {
                $insertStmt->bindValue(":$col", $value);
            }
            $insertStmt->execute();
        }
    } else {
        // No existing item found; insert the new item as is
        $columns = implode(', ', array_keys($itemData));
        $placeholders = implode(', ', array_map(fn($col) => ":$col", array_keys($itemData)));
        $insertQuery = "INSERT INTO items ($columns) VALUES ($placeholders)";
        $insertStmt = $db->prepare($insertQuery);

        foreach ($itemData as $col => $value) {
            $insertStmt->bindValue(":$col", $value);
        }
        $insertStmt->execute();
    }
}

function parseAndUpsertSBOM($db, $jsonFile, $repositoryName, $ecosystem, $dependencyNames, $devDependencyNames): void
{
    // Read and decode the JSON file
    $jsonContent = file_get_contents($jsonFile);
    $data = json_decode($jsonContent, true);

    // Check if components exist in the data
    if (isset($data['components']) && is_array($data['components'])) {
        foreach ($data['components'] as $component) {
            $combinedName = isset($component['group']) ? $component['group'].'/'.$component['name'] : $component['name'];

            if(in_array($combinedName, array_merge($dependencyNames, $devDependencyNames))) {

                $isDev = in_array($combinedName, $devDependencyNames);

                insertPackage($db, $component, $repositoryName, $ecosystem, $isDev);
            }
        }
    }
}

function checkForMissingRiskLevels($db): void
{
    $query = "
        SELECT *
        FROM items AS i1
        WHERE i1.manual_risk_level IS NULL
          AND i1.id = (
              SELECT MAX(i2.id)
              FROM items AS i2
              WHERE i2.ecosystem = i1.ecosystem
                AND i2.bom_ref = i1.bom_ref
          )
    ";

    $stmt = $db->prepare($query);
    $stmt->execute();
    $itemsWithNullRiskLevel = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Step 3: Output a warning for each item
    foreach ($itemsWithNullRiskLevel as $item) {
        echo "- Warning: Item with ecosystem '{$item['ecosystem']}' and bom_ref '{$item['bom_ref']}' has no manual_risk_level.\n";
    }

    echo "Found ".count($itemsWithNullRiskLevel)." items with no manual_risk_level.\n";
}

function transformLicensesString($packageData): string
{
    if (isset($packageData['licenses']) && is_array($packageData['licenses'])) {
        // Extract all 'id' values from the licenses array
        $licenseIds = array_map(function ($licenseEntry) {
            return $licenseEntry['license']['id'] ?? null;
        }, $packageData['licenses']);

        // Filter out any null values (in case some entries are missing 'id')
        $licenseIds = array_filter($licenseIds);

        // Join the IDs into a comma-separated string
        $licenseString = implode(', ', $licenseIds);
    } else {
        // Default value if 'licenses' is not present or not in the expected format
        $licenseString = '';
    }

    return $licenseString;
}

function dbSetup(string $appName): PDO
{
    // Database file path (adjust the path as needed)
    $dbFile = './sboms/sbom-'.$appName.'.sqlite';

    // Open or create the SQLite database
    $db = new PDO('sqlite:' . $dbFile);

    // Create the items table if it doesn't exist
    /**
     * repository
     * ecosystem (z.B. "composer"/"node")
     * asset (z.B. "library")
     * name
     * version
     * bom_ref
     * description (Wenn node: "Frontend - "+description; Wenn composer: "Backend - "+description)
     * author
     * license
     * manual_end_of_support
     * manual_risk_level
     */
    $db->exec("
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            ecosystem TEXT,
            asset TEXT DEFAULT 'library',
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            bom_ref TEXT,
            is_dev BOOLEAN DEFAULT 0,
            description TEXT,
            author TEXT,
            license TEXT,
            manual_end_of_support TEXT,
            manual_risk_level TEXT
        )
    ");

    return $db;
}

function getDependencies($filePath, $key) {
    if (!file_exists($filePath)) {
        return [];
    }

    $data = json_decode(file_get_contents($filePath), true);
    return isset($data[$key]) ? array_keys($data[$key]) : [];
}

$repositoryName = trim(shell_exec('composer show -s --name-only'));
$appName = explode('/', $repositoryName)[1];

$directComposerDependencies = getDependencies('composer.json', 'require');
$directComposerDevDependencies = getDependencies('composer.json', 'require-dev');
$directNodeDependencies = getDependencies('package.json', 'dependencies');
$directNodeDevDependencies = getDependencies('package.json', 'devDependencies');

$db = dbSetup($appName);

parseAndUpsertSBOM(
    db: $db,
    jsonFile: './sboms/sbom-composer.json',
    repositoryName: $repositoryName,
    ecosystem: 'composer',
    dependencyNames: $directComposerDependencies,
    devDependencyNames: $directComposerDevDependencies,
);
parseAndUpsertSBOM(
    db: $db,
    jsonFile: './sboms/sbom-node.json',
    repositoryName: $repositoryName,
    ecosystem: 'node',
    dependencyNames: $directNodeDependencies,
    devDependencyNames: $directNodeDevDependencies,
);

checkForMissingRiskLevels($db);

echo "Data upserted into the database successfully.\n";
