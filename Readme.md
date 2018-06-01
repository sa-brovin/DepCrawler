# DepCrawler
Show report about dependencies between gitlab projects. Optionally can display 2 types of dependency diagrams.

## Dependencies
- python 3.4+
- networkx
- matplotlib

## Usage
```
usage: DepCrawler.py [-h] [--config CONFIG] [--error] [--warning] [--info] [--diag]
                     [applications [applications ...]]

positional arguments:
    applications Limit applications from config to build
    
optional arguments:
  -h, --help       show this help message and exit
  --config CONFIG  configuration JSON-file
  --error          Show only errors on diagram.
  --warning        Show errors and warnings on diagram.
  --info           Show all on diagram.
  --diag           Show diagram.
  ```