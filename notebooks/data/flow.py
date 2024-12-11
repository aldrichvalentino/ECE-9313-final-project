#!/usr/bin/env python3

from nfstream import NFStreamer
import pandas as pd

df1 = NFStreamer(source="s3-eth1.pcap").to_pandas()
df2 = NFStreamer(source="s3-eth2.pcap").to_pandas()

df1.to_csv("data1.csv", index=False)
df2.to_csv("data2.csv", index=False)
