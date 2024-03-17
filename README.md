# HijackLibs-KQL-Detections

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

