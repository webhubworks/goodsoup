<?php

// Database file path (adjust the path as needed)
$dbFile = './sboms/sbom-database.sqlite';

// SBOM JSON files (adjust the paths as needed)
$composerSBOM = './sboms/sbom-composer.json';
$nodeSBOM = './sboms/sbom-node.json';

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
        description TEXT,
        author TEXT,
        license TEXT,
        manual_end_of_support TEXT,
        manual_risk_level TEXT
    )
");

// Function to insert package details into the database
function insertPackage($db, $package, $repositoryName, $ecosystem): void
{

    $stmt = $db->prepare("
        INSERT INTO items (repository, ecosystem, asset, name, version, bom_ref, description, author, license)
        VALUES (:repository, :ecosystem, :asset, :name, :version, :bom_ref, :description, :author, :license)
    ");

    $stmt->execute([
        ':repository' => $repositoryName,
        ':ecosystem' => $ecosystem,
        ':asset' => $package['type'] ?? '',
        ':name' => $package['name'] ?? '',
        ':version' => $package['version'] ?? '',
        ':bom_ref' => $package['bom-ref'] ?? '',
        ':description' => $package['description'] ?? '',
        ':author' => $package['author'] ?? '',
        ':license' => transformLicensesString($package)
    ]);
}

// Function to parse SBOM JSON and insert packages into the database
function parseAndInsertSBOM($db, $jsonFile, $repositoryName, $ecosystem): void
{
    // Read and decode the JSON file
    $jsonContent = file_get_contents($jsonFile);
    $data = json_decode($jsonContent, true);

    // Check if components exist in the data
    if (isset($data['components']) && is_array($data['components'])) {
        foreach ($data['components'] as $component) {
            insertPackage($db, $component, $repositoryName, $ecosystem);
        }
    }
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

$repositoryName = trim(shell_exec('composer show -s --name-only'));

// Parse Composer SBOM JSON
parseAndInsertSBOM($db, $composerSBOM, $repositoryName, 'composer');

// Parse Node.js SBOM JSON
parseAndInsertSBOM($db, $nodeSBOM, $repositoryName, 'node');

echo "Data inserted into the database successfully.\n";
