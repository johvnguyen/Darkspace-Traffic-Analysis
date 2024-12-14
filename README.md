# Team 175 - Darkspace Traffic Analysis

## Introduction
Darkspace traffic is a valuable yet underutilized resource in cybersecurity research. It consists of unsolicited packets that are not expected by any active hosts, and these packets often come from malicious actors testing for vulnerabilities. The challenge lies in the high dimensionality of the data—there are often dozens of attributes per packet—and the large volume, which can make manual analysis impossible. Our project addresses this issue by building a user-friendly, interactive dashboard that leverages data visualization techniques to simplify the complexity of darkspace traffic. Specifically, we employ dimensionality reduction methods, such as t-SNE and UMAP, to transform complex, multi-dimensional data into more comprehensible two-dimensional plots. These visualizations make it easier for analysts to identify and interpret patterns of interest, like clusters of activity that may represent coordinated attacks. Our dataset is the Annotated Anonymized Telescope Packets Sampler dataset from UC San Diego CAIDA (https://catalog.caida.org/dataset/annotated_anonymized_telescope_packets_sampler).

## Package Description
The most important folders in the repo are the following:
* <b>backend</b>: This is where you can find sample data files <i>metadata40k.parquet</i> and <i>timeslices40k.parquet</i>. These are a random 40k sample of the entire dataset after processing. Additionally, <i>server.py</i> contains all of the backend code.
* <b>dashboard</b>: This is where the frontend files are located. The most important file is <i>index.html</i>, which is where most of the frontend code lives.

## Installation
0. Create a new conda environment and install all requirements files

```bash
conda create --name team175 python=3.12
conda activate team175
pip install numpy pandas scikit-learn umap-learn uvicorn fastapi pyarrow fastparquet ipaddress scapy scipy
```
1. Start up the backend

```bash
cd backend
python server.py
```

If you need to change the port from the default of 8081, use `python server.py --port $PORT` and configure the frontend appriopriately.

2. In another terminal, go back to the root directory, and start up the frontend

```bash

python -m http.server 8080

```
3. In your browser, go to http://localhost:8080/dashboard/.

## Execution: Demo

As a quick test to see if your installation has worked, do the following:
* Keep all settings as default, but change
* <b>Max Number of Sample</b> to 500
* click on <b>Compute Transformation</b> to see visualization.

If you select specific regions of the graph, you should see data showing up below.

The dashboard should look like this:

![Diagram](CODE/example_dashboard.png)

Note that server can easily overload your computer as it tries to compute the various techniques.
So look at the server logs to see what it's doing, wait patiently, or limit the amount of samples to small amounts.

## Additional Details

### Available Dashboard Features
Once you are in the dashboard, you should be able to make changes to the following options:
* <b>Features</b>: Select which features you want to include in your analysis.
* <b>Color Selector</b>: Select what you want the coloring to be based on, e.g. based on clustering results, or based on one of the features.
* <b> Dimension Reduction</b>: Select dimension reduction technique. When selecting none, you must only select 2 features.
* <b>Clustering Algorithm </b>: Select which clustering algorithm to use.
* <b>First Timeslice</b>: Select which timeslice to begin with, e.g. "0d23h4m1s" would mean day 0, 11:04:01pm.
* <b>Sample Percent </b>: Determines what percentage of the timeslice data to analyze. Larger dataset will take longer to return results.
* <b>Max Number of Samples</b>: Similar to Sample Percent, determines max number of data points to analyze. Larger dataset will take longer to return results.
* <b>Reduction Hyperparameter</b>: This sets the perplexity hyperparameter of of t-SNE. Larger values mean considering more number of neighbors when determining the similarity of data points.
* <b>Clustering Parameter</b>: When selecting Heuristic Labels, which label to draw on top. When selecting Kmeans and Agglomerative Clustering, this parameter controls the number of clusters. When selecting HDBSCAN, this parameter changes the epsilon value of HDBSCAN, which defines the maximum distance for points to be considered as neighbors; the current approach is to do epsilon-div10, or divide epsilon by 10, for HDBSCAN.
* <b>Timeslice Length</b>: Select how long of a timeslice you want to analyze, e.g. 12h would mean a timeslice of 12 hours.
* <b>Timeslice Highlighting</b>: Highlight a region of samples and the individual packet data will be shown below the graph. Note that the table is limited to the first 20k entries, to prevent your browser from running out of memory.


### Parse timeslices from .pcaps
In the pcap_analysis/ directory, we store all the code necessary to convert the .pcap files found in the Annotated Anonymized Telescope Packets Sampler dataset into the Parquet files used by our dashboard. Note that the Annotated Anonymized Telescope Packets Sampler dataset consists of 168 files and their corresponding metadata, amounting to 11 GB of data. It takes an extended amount of time, to process all of these files.

0. Enter the pcap_analysis/ directory and install dependencies

```bash
cd pcap_analysis
# skip if done earlier
conda create --name team175 python=3.12

conda activate team175
pip install numpy pandas scikit-learn umap-learn uvicorn fastapi pyarrow fastparquet ipaddress scapy scipy
```

1. Make output directory
```bash
mkdir db
mkdir db/merged/
mkdir db/timeslices/
mkdir db/metadata/
```

2. Download the Annotated Anonymized Telescope Packets Sampler
```bash
wget https://publicdata.caida.org/datasets/security/telescope-annotated-anonymized-sampler/telescopesampleanon.tar.gz
mkdir telescopesampleanon
tar -xvxf telescopesampleanon.tar.gz -C telescopesampleanon
```

3. Run the parsing script
* Note: This script will parse each .pcap file in telescopesampleanon/pcapsanon into a .parquet file in db/timeslices/. Its metadata will be stored in a similarly named file in db/metadata/
* __WARNING__: This script takes a long time to finish. Using 100 threads, processing this data took over 12 hours.
```bash
python create_timeslices.py --nthreads 1
```

4. Run the merge sript to combine the various .parquet timeslice and metadata files into a singular dataset, creating an index in order to associate each timeslice and its metadata.
```bash
python merge_parquets.py
```

5. At the end, you will have a db/merged/timeslice.parquet and db/merged/metadata.parquet file(s) used by the dashboard. Move them to backend/
