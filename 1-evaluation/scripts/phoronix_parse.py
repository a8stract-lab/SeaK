import re
import sys


def extract_content(html_string):
    match = re.search(r'<[^>]+>(.*?)<\/[^>]+>', html_string.strip())
    if match:
        return match.group(1)
    return "Error"

def main(argv):
    benchmark_names = ["Sockperf","OSBench","FFmpeg","7-Zip Compression","OpenSSL","Redis","SQLite Speedtest","Apache HTTP Server"]
    benchmark_maps_choose_value = {"Sockperf":1,"OSBench":1,"FFmpeg":1,"7-Zip Compression":1,"OpenSSL":1,"Redis":1,"SQLite Speedtest":1,"Apache HTTP Server":1}
    benchmark_maps = {"Sockperf":[],"OSBench":[],"FFmpeg":[],"7-Zip Compression":[],"OpenSSL":[],"Redis":[],"SQLite Speedtest":[],"Apache HTTP Server":[]}
    filename = argv[1]
    flag = False
    title = ""
    with open(filename) as file:
        for line in file:
            if "Title" in line and flag is False:
                title = extract_content(line)
                if title in benchmark_names:
                    flag = True
                    continue
            if flag is True:
                if "Value" in line:
                    value = extract_content(line)
                    benchmark_maps[title].append(value)
                    flag = False
    print(benchmark_maps)
    with open(argv[2],"w") as file:
        for key in benchmark_maps:
            file.write(key+":"+benchmark_maps[key][benchmark_maps_choose_value[key]-1]+"\n")

if __name__ == "__main__":
    main(sys.argv)