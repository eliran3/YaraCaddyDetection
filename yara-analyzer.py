import yara
import argparse
import ntpath

def Analyze_Results(data):
    if data['meta'] and data['meta']['primary']:
        print("Found Malware")
        return yara.CALLBACK_ABORT

def main():
    parser = argparse.ArgumentParser(description="Tool to run yara files with externals")
    parser.add_argument("-yar", "--yara_file", required=True, help="Path to the yara rules file")
    parser.add_argument("-file", "--target_file", required=True, help="Path to the file to analyze")
    args = parser.parse_args()

    rules = yara.compile(filepath=args.yara_file, externals={'filelength': len(ntpath.basename(args.target_file).split('.')[0])})
    rules.match(args.target_file, callback=Analyze_Results, which_callbacks=yara.CALLBACK_MATCHES)

if __name__ == '__main__':
    main()
