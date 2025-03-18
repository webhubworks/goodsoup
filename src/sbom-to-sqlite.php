<?php

use Carbon\Carbon;
use Composer\Semver\Semver;
use Illuminate\Database\Capsule\Manager as Capsule;
use Symfony\Component\VarDumper\VarDumper;
use Webhubworks\Goodsoup\Models\Item;
use Webhubworks\Goodsoup\Models\Vulnerability;

// Autoload Composer dependencies
require __DIR__ . '/../vendor/autoload.php';

function upsertPackage($package, $repositoryName, $ecosystem, $isDev, $latestVersion, $toBeReplacedBy, $vulnerabilities): void
{
    $columnsToCompareForChanges = [
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
        'to_be_replaced_by',
        'description',
        'author',
        'license',
    ];
    $manualColumns = ['manual_end_of_support', 'manual_risk_level'];

    $itemData = [
        'repository' => $repositoryName,
        'ecosystem' => $ecosystem,
        'asset' => $package['type'] ?? '',
        'name' => $package['name'] ?? '',
        'version' => $package['version'] ?? '',
        'latest_version' => $latestVersion ?? '',
        'is_newer_version_available' => (bool) version_compare($package['version'], $latestVersion, '<'),
        'bom_ref' => $package['bom-ref'] ?? '',
        'is_dev' => (bool) $isDev ?? false,
        'is_abandoned' => $toBeReplacedBy !== null,
        'to_be_replaced_by' => $toBeReplacedBy,
        'description' => $package['description'] ?? '',
        'author' => $package['author'] ?? '',
        'license' => transformLicensesString($package),
        'manual_end_of_support' => null,
        'manual_risk_level' => null,
    ];

    /**
     * Find an existing item based on non-manual columns
     */
    /** @var Item $item */
    $item = Item::query()
        ->where('ecosystem', $itemData['ecosystem'])
        ->where('bom_ref', $itemData['bom_ref'])
        ->orderBy('id', 'desc')
        ->first();

    if ($item) {
        /**
         * Compare normal columns to see if there's a difference
         */
        $changes = [];
        foreach ($columnsToCompareForChanges as $col) {
            if ($item[$col] !== $itemData[$col]) {
                $changes[] = $col;
                break;
            }
        }

        if (count($changes) > 0) {
            echo "Changes detected for column(s) ".implode(', ', $changes).".\n";

            foreach ($manualColumns as $manualCol) {
                $itemData[$manualCol] = $item[$manualCol];
            }

            $item = Item::create($itemData);
            upsertVulnerabilitiesPerItem($item, $vulnerabilities);

            return;
        }

        $item->touch();
        upsertVulnerabilitiesPerItem($item, $vulnerabilities);

        return;
    }

    $item = Item::create($itemData);
    upsertVulnerabilitiesPerItem($item, $vulnerabilities);
}

function upsertVulnerabilitiesPerItem(Item $item, ?array $vulnerabilities = null): void
{
    $item->vulnerabilities()->delete();

    if($vulnerabilities === null) {
        return;
    }

    if($item->ecosystem === 'composer'){
        foreach($vulnerabilities as $vulnerability){
            createVulnerability($item, $vulnerability);
        }
    } else {
        createVulnerability($item, $vulnerabilities);
    }

    $item->refresh();

    $latestReportedVulnerability = $item->vulnerabilities->sortByDesc('reported_at')->first();
    $affectedVersions = explode('|', $latestReportedVulnerability->affected_versions);

    $isLatestVersionAffected = false;

    foreach ($affectedVersions as $range) {
        if(! version_compare( $range, '0.0.1', '>=')){
            continue;
        }

        if (Semver::satisfies($item->latest_version, $range)) {
            $isLatestVersionAffected = true;
            break;
        }
    }

    /**
     * Actively maintained:
     * - Latest version is not affected OR
     * - Latest reported vulnerability is less than 30 days old
     */
    $item->update([
        'is_actively_maintained' => !$isLatestVersionAffected || ($latestReportedVulnerability->reported_at && Carbon::parse($latestReportedVulnerability->reported_at)->diffInDays() < 30),
    ]);
}

function createVulnerability(Item $item, array $vulnerability): void
{
    $title = match($item->ecosystem){
        'composer' => $vulnerability['title'] ?? '???',
        'node' => $vulnerability['name'] ?? '???',
        default => '???'
    };

    $url = match($item->ecosystem){
        'composer' => $vulnerability['link'] ?? '',
        'node' => $vulnerability['via'][0]['url'] ?? '',
        default => ''
    };

    $affectedVersions = match($item->ecosystem){
        'composer' => $vulnerability['affectedVersions'] ?? '',
        'node' => $vulnerability['range'] ?? '',
        default => ''
    };

    $advisoryId = match($item->ecosystem){
        'composer' => $vulnerability['id'] ?? null,
        'node' => $vulnerability['via'][0]['source'] ?? null,
        default => null
    };

    $item->vulnerabilities()->create([
        'ecosystem' => $item->ecosystem,
        'package_name' => $item->name,
        'title' => $title,
        'url' => $url,
        'severity' => $vulnerability['severity'] ?? 'unknown',
        'affected_versions' => $affectedVersions,
        'cve' => $vulnerability['cve'] ?? null,
        'cwe' => isset($vulnerability['via'][0]['cwe']) ? implode(', ', $vulnerability['via'][0]['cwe']) : null,
        'advisory_id' => $advisoryId,
        'reported_at' => $vulnerability['reportedAt'] ?? null,
    ]);
}

function parseAndUpsertSBOM($jsonFile, $repositoryName, $ecosystem, $dependencyNames, $devDependencyNames, $outdatedDependencies, $abandonedPackages, $vulnerabilities): void
{
    $jsonContent = file_get_contents($jsonFile);
    $data = json_decode($jsonContent, true);

    if (! isset($data['components']) || ! is_array($data['components'])) {
        return;
    }

    foreach ($data['components'] as $component) {
        $combinedName = isset($component['group']) ? $component['group'].'/'.$component['name'] : $component['name'];

        if(! in_array($combinedName, array_merge($dependencyNames, $devDependencyNames))) {
            continue;
        }

        $outdatedDependency = array_values(array_filter($outdatedDependencies, function ($dependency) use ($combinedName) {
            return $dependency['name'] === $combinedName;
        }));
        if(isset($outdatedDependency[0])) {
            $latestVersion = $outdatedDependency[0]['latest'] ?? $component['version'];
        } else {
            $latestVersion = $component['version'];
        }

        upsertPackage(
            package: $component,
            repositoryName: $repositoryName,
            ecosystem: $ecosystem,
            isDev: in_array($combinedName, $devDependencyNames),
            latestVersion: $latestVersion,
            toBeReplacedBy: $abandonedPackages[$combinedName] ?? null,
            vulnerabilities: $vulnerabilities[$combinedName] ?? null,
        );
    }
}

function checkForMissingRiskLevels(): void
{
    $itemsWithNullRiskLevel = Item::query()
        ->whereNull('manual_risk_level')
        ->whereIn('id', function ($query) {
            $query->selectRaw('MAX(id)')
                ->from('items as i2')
                ->whereColumn('i2.ecosystem', 'items.ecosystem')
                ->whereColumn('i2.bom_ref', 'items.bom_ref');
        })
        ->get()
        ->toArray();

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

function dbSetup(string $appName): void
{
    // Database file path (adjust the path as needed)
    $dbFile = './sboms/sbom-'.$appName.'.sqlite';

    // Create the SQLite database file if it doesn't exist
    if (!file_exists($dbFile)) {
        touch($dbFile); // Create an empty file
    }

    // Initialize Eloquent
    $capsule = new Capsule;

    $capsule->addConnection([
        'driver'    => 'sqlite',
        'database'  => $dbFile,
        'prefix'    => '',
    ]);

    // Set the global Eloquent instance
    $capsule->setAsGlobal();
    $capsule->bootEloquent();

    if (!Capsule::schema()->hasTable('items')) {
        Capsule::schema()->create('items', function ($table) {
            $table->increments('id');

            $table->string('repository');
            $table->string('ecosystem')->nullable();
            $table->string('asset')->default('library');
            $table->string('name');
            $table->string('version');
            $table->string('latest_version');
            $table->boolean('is_newer_version_available')->default(0);
            $table->string('bom_ref')->nullable();
            $table->boolean('is_dev')->default(0);
            $table->boolean('is_abandoned')->default(0);
            $table->string('to_be_replaced_by')->nullable();
            $table->boolean('is_actively_maintained')->default(1);
            $table->text('description')->nullable();
            $table->string('author')->nullable();
            $table->string('license')->nullable();
            $table->string('manual_end_of_support')->nullable();
            $table->string('manual_risk_level')->nullable();

            $table->timestamps();
        });
    }

    if (!Capsule::schema()->hasTable('vulnerabilities')) {
        Capsule::schema()->create('vulnerabilities', function ($table) {
            $table->increments('id');

            $table->foreignId('item_id')->constrained('items')->cascadeOnDelete();
            $table->string('ecosystem');
            $table->string('package_name');
            $table->string('title');
            $table->string('url');
            $table->string('severity');
            $table->string('affected_versions');

            $table->string('cve')->nullable();
            $table->string('cwe')->nullable();
            $table->string('advisory_id')->nullable();

            $table->timestamp('reported_at')->nullable();
            $table->timestamps();
        });
    }
}

function getDependencies($filePath, $key) {
    if (!file_exists($filePath)) {
        return [];
    }

    $data = json_decode(file_get_contents($filePath), true);
    return isset($data[$key]) ? array_keys($data[$key]) : [];
}

function dd(mixed ...$vars): never
{
    if (!\in_array(\PHP_SAPI, ['cli', 'phpdbg', 'embed'], true) && !headers_sent()) {
        header('HTTP/1.1 500 Internal Server Error');
    }

    if (array_key_exists(0, $vars) && 1 === count($vars)) {
        VarDumper::dump($vars[0]);
    } else {
        foreach ($vars as $k => $v) {
            VarDumper::dump($v, is_int($k) ? 1 + $k : $k);
        }
    }

    exit(1);
}

$repositoryName = trim(shell_exec('composer show -s --name-only'));
$appName = explode('/', $repositoryName)[1];

echo "Gathering composer data...\n";
$directComposerDependencies = getDependencies('composer.json', 'require');
$directComposerDevDependencies = getDependencies('composer.json', 'require-dev');
$outdatedComposerDependencies = shell_exec('composer outdated --ignore-platform-reqs --format=json');
$outdatedComposerDependencies = json_decode($outdatedComposerDependencies, true);
$composerAudit = shell_exec('composer audit --format=json');
$composerAudit = json_decode($composerAudit, true);
$composerVulnerabilities = $composerAudit['advisories'] ?? [];
$composerAbandonedPackages = $composerAudit['abandoned'] ?? [];

echo "Gathering node data...\n";
$directNodeDependencies = getDependencies('package.json', 'dependencies');
$directNodeDevDependencies = getDependencies('package.json', 'devDependencies');
$outdatedNodeDependencies = shell_exec('npm outdated --json');
$outdatedNodeDependencies = json_decode($outdatedNodeDependencies, true);
$outdatedNodeDependencies = array_map(function ($key, $dependency) {
    return [
        'name' => $key,
        'version' => $dependency['current'],
        'latest' => $dependency['latest'],
        'abandoned' => $dependency['wanted'] === 'abandoned',
    ];
}, array_keys($outdatedNodeDependencies), $outdatedNodeDependencies);
$nodeAudit = shell_exec('npm audit --json');
$nodeAudit = json_decode($nodeAudit, true);
$nodeVulnerabilities = $nodeAudit['vulnerabilities'] ?? [];

dbSetup($appName);

parseAndUpsertSBOM(
    jsonFile: './sboms/sbom-composer.json',
    repositoryName: $repositoryName,
    ecosystem: 'composer',
    dependencyNames: $directComposerDependencies,
    devDependencyNames: $directComposerDevDependencies,
    outdatedDependencies: $outdatedComposerDependencies['installed'] ?? [],
    abandonedPackages: $composerAbandonedPackages,
    vulnerabilities: $composerVulnerabilities,
);
parseAndUpsertSBOM(
    jsonFile: './sboms/sbom-node.json',
    repositoryName: $repositoryName,
    ecosystem: 'node',
    dependencyNames: $directNodeDependencies,
    devDependencyNames: $directNodeDevDependencies,
    outdatedDependencies: $outdatedNodeDependencies,
    abandonedPackages: [],
    vulnerabilities: $nodeVulnerabilities,
);

checkForMissingRiskLevels();

echo "Data upserted into the database successfully.\n";
