const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

/* ALLOWED_LICENSES.txt file contains list of known good licenses loosely
** based on https://docs.fedoraproject.org/en-US/legal/allowed-licenses/
*/
const approvedLicenses = fs.readFileSync(path.resolve(__dirname, 'ALLOWED_LICENSES.txt'), 'utf-8')
  .split('\n')
  .map(line => line.trim())
  .filter(line => line);

const options = {
  sbom: { type: 'string', short: 's' },
  baselineSBOM: { type: 'string', short: 'b' }
};

const {
  values: { sbom, baselineSBOM }
} = parseArgs({ options });

if (!sbom) {
  console.error('Usage: node sbom-license-check --sbom <path> [--baselineSBOM <path>]');
  process.exit(1);
}

const sbomPath = path.resolve(sbom);
const baselineSBOMPath = baselineSBOM ? path.resolve(baselineSBOM) : null;

if (!fs.existsSync(sbomPath) || (baselineSBOMPath && !fs.existsSync(baselineSBOMPath))) {
  console.error('One or both input files do not exist');
  process.exit(1);
}

let sbomData, baselineSBOMData;
try {
  sbomData = JSON.parse(fs.readFileSync(sbomPath, 'utf-8'));
  if (baselineSBOMPath) {
    baselineSBOMData = JSON.parse(fs.readFileSync(baselineSBOMPath, 'utf-8'));
  }
} catch (error) {
  console.error('Error reading or parsing one of the input files:', error.message);
  process.exit(1);
}

const components = sbomData.components || [];
let filteredComponents;

if (baselineSBOMData) {
  const baselineComponentsPurls = new Set(baselineSBOMData.components.map(component => component.purl));
  const newComponents = components.filter(component => !baselineComponentsPurls.has(component.purl));
  filteredComponents = filterComponentsWithUnapprovedLicenses(newComponents);
} else {
  filteredComponents = filterComponentsWithUnapprovedLicenses(components);
}

if (filteredComponents.length === 0) {
  console.log('No components with unapproved licenses found.');
} else {
  displayFilteredComponents(filteredComponents);
}

function filterComponentsWithUnapprovedLicenses (components) {
  return components.filter(component => {
    const licenses = component.licenses || [];
    return licenses.some(license => isUnapprovedLicense(license));
  });
}

function isUnapprovedLicense (license) {
  if (!license || !license.license || !license.license.id) {
    return false;
  }
  return !approvedLicenses.includes(license.license.id);
}

function displayFilteredComponents (components) {
  console.table(components.map(component => ({
    'Component Name': component.name || 'N/A',
    pURL: component.purl || 'N/A',
    License: (component.licenses || []).map(license => license.license.id || 'Unknown').join(', '),
    Location: component.properties?.find(prop => prop.name === 'syft:location:0:path')?.value || 'N/A'
  })));
}
