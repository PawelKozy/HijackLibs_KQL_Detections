# HijackLibs KQL Detections (ARCHIVED)
Status: Archived

This repository has been archived. The detection methods in this repository, which were based on static KQL queries, have been deprecated.
All future development, including the use of the externaldata operator for dynamic and scalable detection queries, has been migrated to a new repository:

New Repository:

For a practical example of using the `externaldata` operator with HijackLibs, see [this blog post](https://medium.com/@kozielpawe/detecting-dll-sideloading-and-vulnerable-driver-loads-using-hijacklibs-and-loldrivers-apis-e18a0c4b8ce1). The article outlines a more flexible approach that keeps your detection queries up to date.

## Overview
This repository hosts a collection of Kusto Query Language (KQL) detections based on the HijackLibs dataset. It aims to provide security researchers and practitioners with tools to detect DLL sideloading, environment variable manipulation, phantom DLLs, and search order hijacking activities.

## Structure
- **GeneralDetections**: Broad detections that apply across various hijacking techniques.
- **IndividualDetections**: Specific detections tailored to each hijackable DLL.
- **Scripts**: Utility scripts for generating and managing detections.
- **Tests**: Scripts for testing the effectiveness and accuracy of detections.

## Usage
To use these detections, navigate to the specific folder for the detection type you're interested in. 
Or run TransformerKql.py that will query up to date data from hijacklibs and create queires for you. 

### General Detections
For broad coverage, explore the `GeneralDetections` directory.

### Specific Detections
For technique-specific detections, check the corresponding directories under `IndividualDetections`.

Please ensure your contributions are well-documented and include any relevant test cases.

## Acknowledgments
This project leverages data from the [HijackLibs project](https://hijacklibs.net). Special thanks to the contributors of HijackLibs for compiling the dataset.

