#!/usr/bin/env python3

import argparse
import sys
import yaml

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract CA data from kubeconfig')
    parser.add_argument('--kubeconfig', help='The location of the kubeconfig to extract from.')
    parser.add_argument('--cluster', help='The kubeconfig cluster entry to extract from.')
    args = parser.parse_args()
    if args.kubeconfig == None:
        print('--kubeconfig is required', file=sys.stderr)
        sys.exit(1)
    if args.cluster == None:
        print('--cluster is required', file=sys.stderr)
        sys.exit(1)
    kubeconfig = args.kubeconfig
    cluster = args.cluster
    with open(kubeconfig, 'r') as f:
        config = yaml.safe_load(f)
        clusters = config['clusters']
        for c in clusters:
            if c['name'] == cluster:
                print(c['cluster']['certificate-authority-data'])
                break
        else:
            print(f"Cluster {cluster} was not found in {kubeconfig}.", file=sys.stderr)
            sys.exit(1)
