# HijackLibs-Detections

## Overview
This repository hosts a collection of Kusto Query Language (KQL) detections based on the HijackLibs dataset. It aims to provide security researchers and practitioners with tools to detect DLL sideloading, environment variable manipulation, phantom DLLs, and search order hijacking activities.

## Structure
- **GeneralDetections**: Broad detections that apply across various hijacking techniques.
- **IndividualDetections**: Specific detections tailored to each hijacking technique, including Sideloading, Environment Variable, Phantom, and Search Order.
- **Scripts**: Utility scripts for generating and managing detections.
- **Data**: Raw data files used for generating detections.
- **Tests**: Scripts for testing the effectiveness and accuracy of detections.

## Usage
To use these detections, navigate to the specific folder for the detection type you're interested in. Each folder contains a `README.md` with detailed instructions on how to deploy and interpret the detections.

### General Detections
For broad coverage, explore the `GeneralDetections` directory.

### Specific Detections
For technique-specific detections, check the corresponding directories under `IndividualDetections`.

Please ensure your contributions are well-documented and include any relevant test cases.

## Acknowledgments
This project leverages data from the [HijackLibs project](https://hijacklibs.net). Special thanks to the contributors of HijackLibs for compiling the dataset.
