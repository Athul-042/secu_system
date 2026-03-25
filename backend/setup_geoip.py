import urllib.request
import gzip
import shutil
import os

url = "https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz"
out_gz = "data/GeoLite2-Country.mmdb.gz"
out_mmdb = "data/GeoLite2-Country.mmdb"

os.makedirs("data", exist_ok=True)

print(f"Downloading {url}...")
try:
    with urllib.request.urlopen(url) as response, open(out_gz, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
    print("Download complete. Decompressing...")

    with gzip.open(out_gz, 'rb') as f_in:
        with open(out_mmdb, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    print(f"Success! GeoIP database saved to {out_mmdb}")
    os.remove(out_gz)
except Exception as e:
    print(f"Error during GeoIP setup: {e}")
