from os import listdir
import os
import pprint
import pandas as pd

timeslice_files = listdir("./db/timeslices/")
metadata_files = listdir("./db/metadata/")

fnames = [os.path.basename(timeslice_file) for timeslice_file in timeslice_files]

timeslice_dfs = [pd.read_parquet(f'./db/timeslices/{file}') for file in timeslice_files]
merged_ts_df = pd.concat(timeslice_dfs, ignore_index = True)
merged_ts_df['index'] = range(1, len(merged_ts_df) + 1)

metadata_dfs = [pd.read_parquet(f'./db/metadata/{file}') for file in metadata_files]
merged_meta_df = pd.concat(metadata_dfs, ignore_index = True)
orig_meta_df = merged_meta_df.copy(deep = True)

indexed_meta_df = merged_meta_df.merge(merged_ts_df[['index', 'timeslice', 'src_ip']],
                                       left_on = ['timeslice', 'source_ip'],
                                       right_on = ['timeslice', 'src_ip'],
                                       how = 'left')

indexed_meta_df.drop('src_ip', axis = 1, inplace = True)

print(indexed_meta_df)
merged_ts_df.to_csv('./db/merged/timeslices.csv', index = False)
indexed_meta_df.to_csv('./db/merged/metadata.csv', index = False)

merged_ts_df.to_parquet('./db/merged/timeslices.parquet')
indexed_meta_df.to_parquet('./db/merged/metadata.parquet')

ts_40k = merged_ts_df.sample(n=40000, random_state=42)
meta_40k = pd.merge(ts_40k['index'], indexed_meta_df, how='inner')
print(meta_40k.columns)

ts_40k.to_csv('./db/merged/timeslices_40k.csv', index = False)
meta_40k.to_csv('./db/merged/metadata_40k.csv', index = False)

ts_40k.to_parquet('./db/merged/timeslices_40k.parquet')
meta_40k.to_parquet('./db/merged/metadata_40k.parquet')
