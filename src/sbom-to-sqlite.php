<?php

function insertPackage($db, $package, $repositoryName, $ecosystem, $isDev, $latestVersion, $isAbandoned): void
{
    $normalColumns = [
        'repository',
        'ecosystem',
        'asset',
        'name',
        'version',
        'latest_version',
        'is_newer_version_available',
        'bom_ref',
        'is_dev',
        'is_abandoned',
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
        'latest_version' => $latestVersion ?? '',
        'is_newer_version_available' => (int) version_compare($package['version'], $latestVersion, '<'),
        'bom_ref' => $package['bom-ref'] ?? '',
        'is_dev' => (int) $isDev ?? 0,
        'is_abandoned' => (int) $isAbandoned ?? 0,
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
            if ($existingItem[$col] !== $itemData[$col]) {
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

function parseAndUpsertSBOM($db, $jsonFile, $repositoryName, $ecosystem, $dependencyNames, $devDependencyNames, $outdatedDependencies): void
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
                $outdatedDependency = array_filter($outdatedDependencies, function ($dependency) use ($combinedName) {
                    return $dependency['name'] === $combinedName;
                });
                $outdatedDependency = reset($outdatedDependency);
                if(isset($outdatedDependency) && is_array($outdatedDependency)) {
                    $isAbandoned = (bool)$outdatedDependency['abandoned'] ?? false;
                    $latestVersion = $outdatedDependency['latest'] ?? $component['version'];
                } else {
                    $isAbandoned = false;
                    $latestVersion = $component['version'];
                }

                insertPackage($db, $component, $repositoryName, $ecosystem, $isDev, $latestVersion, $isAbandoned);
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

    $db->exec("
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repository TEXT NOT NULL,
            ecosystem TEXT,
            asset TEXT DEFAULT 'library',
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            latest_version TEXT NOT NULL,
            is_newer_version_available BOOLEAN DEFAULT 0,
            bom_ref TEXT,
            is_dev BOOLEAN DEFAULT 0,
            is_abandoned BOOLEAN DEFAULT 0,
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
$outdatedComposerDependencies = shell_exec('composer outdated --format=json');
$outdatedComposerDependencies = json_decode($outdatedComposerDependencies, true);
$directNodeDependencies = getDependencies('package.json', 'dependencies');
$directNodeDevDependencies = getDependencies('package.json', 'devDependencies');
$outdatedNodeDependencies = shell_exec('npm outdated --json');
$outdatedNodeDependencies = json_decode($outdatedNodeDependencies, true);
// Map associative array to simple array with 'name', 'version', 'latest', 'abandoned' keys
$outdatedNodeDependencies = array_map(function ($key, $dependency) {
    return [
        'name' => $key,
        'version' => $dependency['current'],
        'latest' => $dependency['latest'],
        'abandoned' => $dependency['wanted'] === 'abandoned',
    ];
}, array_keys($outdatedNodeDependencies), $outdatedNodeDependencies);

$db = dbSetup($appName);

parseAndUpsertSBOM(
    db: $db,
    jsonFile: './sboms/sbom-composer.json',
    repositoryName: $repositoryName,
    ecosystem: 'composer',
    dependencyNames: $directComposerDependencies,
    devDependencyNames: $directComposerDevDependencies,
    outdatedDependencies: $outdatedComposerDependencies['installed'] ?? [],
);
parseAndUpsertSBOM(
    db: $db,
    jsonFile: './sboms/sbom-node.json',
    repositoryName: $repositoryName,
    ecosystem: 'node',
    dependencyNames: $directNodeDependencies,
    devDependencyNames: $directNodeDevDependencies,
    outdatedDependencies: $outdatedNodeDependencies,
);

checkForMissingRiskLevels($db);

echo "Data upserted into the database successfully.\n";
