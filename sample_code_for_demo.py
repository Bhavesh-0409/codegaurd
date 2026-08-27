# Sample file for demoing Sentinel's code scan feature.
# Mix of a clean package, a likely-typosquat, and a plausible hallucinated package name.

import requests            # clean - real, popular package
import reqeusts            # typosquat - one edit away from "requests"
import pandas_fast_utils   # likely hallucinated - plausible LLM-style name, probably doesn't exist
import numpy as np         # clean

def fetch_data(url):
    response = requests.get(url)
    return response.json()

def process(df):
    return np.mean(df)
