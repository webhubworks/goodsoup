#!/bin/bash

# Generating the SBOM for composer packages
echo "Generating the SBOM for composer packages..."
composer CycloneDX:make-sbom --omit=dev --spec-version=1.3 --output-format=JSON --output-file="./sboms/sbom-composer.json"
echo "Done."

# Generating the SBOM for node packages
echo "Generating the SBOM for node packages..."
vendor/webhubworks/goodsoup/cyclonedx-npm  --spec-version=1.3 --output-format=json --output-file="./sboms/sbom-node.json"
echo "Done."

# Gathering the data and fill them into a sqlite database
echo "Gathering the data and fill them into a sqlite database..."
php vendor/webhubworks/goodsoup/sbom-to-sqlite.php