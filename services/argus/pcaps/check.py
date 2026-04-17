from nfstream import NFStreamer
import pandas as pd

df = NFStreamer(source='wannacry.pcap', statistical_analysis=True).to_pandas()
print(df.shape)
print(df.columns.tolist())

df.to_csv("out.csv")
