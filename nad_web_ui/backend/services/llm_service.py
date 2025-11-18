#!/usr/bin/env python3
"""
LLM 服務 - 使用 OpenAI API 進行安全分析
"""
import json
import ipaddress
import yaml
from typing import Dict, Optional
from config import Config


class LLMService:
    """LLM 安全分析服務"""

    def __init__(self):
        """初始化 LLM 服務"""
        self.api_key = Config.OPENAI_API_KEY
        self.model = Config.LLM_MODEL
        self.enabled = Config.LLM_ENABLED
        self.device_mapping = self._load_device_mapping()

    def analyze_ip_security(self, data: Dict) -> Dict:
        """
        使用 LLM 分析 IP 的安全狀況

        Args:
            data: 包含以下欄位的字典：
                - analysis_data: IP 分析數據（必需，除非提供 custom_prompt）
                - model_id: 要使用的模型 ID（選填，預設使用配置的模型）
                - use_openrouter: 是否使用 OpenRouter（選填，預設 False）
                - custom_prompt: 自定義提示詞（選填，覆蓋預設提示詞）
                - response_format: 回應格式（選填，'json' 表示 JSON 模式）

        Returns:
            LLM 分析結果
        """
        # 提取參數
        analysis_data = data.get('analysis_data')
        model_id = data.get('model_id', self.model)
        use_openrouter = data.get('use_openrouter', False)
        custom_prompt = data.get('custom_prompt')
        response_format = data.get('response_format')
        dry_run = data.get('dry_run', False)  # 僅返回提示詞，不調用 LLM

        # 檢查 API 金鑰
        if use_openrouter:
            if not Config.OPENROUTER_API_KEY:
                return {
                    'status': 'disabled',
                    'error': 'OpenRouter API 金鑰未設置，請設置 OPENROUTER_API_KEY 環境變數'
                }
            api_key = Config.OPENROUTER_API_KEY
            api_base = Config.OPENROUTER_API_BASE
        else:
            if not self.enabled:
                return {
                    'status': 'disabled',
                    'error': 'LLM 功能未啟用，請設置 OPENAI_API_KEY 環境變數'
                }
            api_key = self.api_key
            api_base = None

        try:
            import openai

            # 建立客戶端
            if use_openrouter:
                client = openai.OpenAI(
                    api_key=api_key,
                    base_url=api_base
                )
            else:
                client = openai.OpenAI(api_key=api_key)

            # 準備提示詞
            if custom_prompt:
                prompt = custom_prompt
            else:
                if not analysis_data:
                    return {
                        'status': 'error',
                        'error': 'analysis_data 或 custom_prompt 至少需要提供一個'
                    }
                # 準備分析數據摘要
                summary = self._prepare_analysis_summary(analysis_data)
                # 構建提示詞
                prompt = self._build_security_prompt(summary)

            # 如果是 dry_run 模式，直接返回提示詞
            if dry_run:
                return {
                    'status': 'success',
                    'prompt': prompt,
                    'model': model_id,
                    'dry_run': True
                }

            # 準備 API 參數
            api_params = {
                "model": model_id,
                "messages": [
                    {
                        "role": "system",
                        "content": "你是一位網路安全專家，擅長分析 NetFlow 數據並識別潛在的安全威脅。請用繁體中文回答。"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.3,
                "max_tokens": 2000
            }

            # 如果使用 OpenRouter，添加額外標頭
            if use_openrouter:
                api_params["extra_headers"] = {
                    "HTTP-Referer": Config.OPENROUTER_SITE_URL,
                    "X-Title": Config.OPENROUTER_APP_NAME
                }

            # 如果需要 JSON 格式回應
            if response_format == 'json':
                api_params["response_format"] = {"type": "json_object"}

            # 調用 API
            response = client.chat.completions.create(**api_params)

            analysis_text = response.choices[0].message.content

            return {
                'status': 'success',
                'analysis': analysis_text,
                'model': model_id,
                'tokens_used': {
                    'prompt': response.usage.prompt_tokens if response.usage else 0,
                    'completion': response.usage.completion_tokens if response.usage else 0,
                    'total': response.usage.total_tokens if response.usage else 0
                }
            }

        except ImportError:
            return {
                'status': 'error',
                'error': '請安裝 openai 套件: pip install openai'
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': f'LLM 分析失敗: {str(e)}'
            }

    def _load_device_mapping(self) -> Optional[Dict]:
        """載入設備 IP 映射配置"""
        try:
            device_mapping_path = Config.NAD_BASE_PATH + '/nad/device_mapping.yaml'
            with open(device_mapping_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"載入設備映射配置失敗: {str(e)}")
            return None

    def _get_ip_info(self, ip: str) -> Optional[Dict]:
        """
        查詢 IP 的 WHOIS 和 AS 資訊

        Args:
            ip: IP 地址

        Returns:
            IP 資訊字典，如果查詢失敗則返回 None
        """
        try:
            # 檢查是否為公網 IP
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                # 私有 IP - 包含設備映射信息
                ip_info = {
                    'is_public': False,
                    'type': 'Private IP',
                    'device_mapping': self.device_mapping
                }
                return ip_info

            # 查詢公網 IP 的 WHOIS 資訊
            from ipwhois import IPWhois

            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)

            # 提取關鍵資訊
            ip_info = {
                'is_public': True,
                'asn': result.get('asn'),
                'asn_cidr': result.get('asn_cidr'),
                'asn_country_code': result.get('asn_country_code'),
                'asn_description': result.get('asn_description'),
                'asn_registry': result.get('asn_registry'),
                'network_name': result.get('network', {}).get('name'),
                'network_handle': result.get('network', {}).get('handle'),
                'network_country': result.get('network', {}).get('country'),
            }

            # 嘗試獲取組織資訊
            if result.get('objects'):
                for obj_key, obj_data in result['objects'].items():
                    if obj_data.get('contact', {}).get('name'):
                        ip_info['org_name'] = obj_data['contact']['name']
                        break

            return ip_info

        except Exception as e:
            print(f"查詢 IP 資訊失敗: {str(e)}")
            return None

    def _prepare_analysis_summary(self, data: Dict) -> Dict:
        """準備分析數據摘要"""
        ip = data.get('ip')

        # 查詢 IP 資訊
        ip_info = self._get_ip_info(ip) if ip else None

        summary = {
            'ip': ip,
            'ip_info': ip_info,
            'device_type': data.get('device_type'),
            'time_range': data.get('time_range', {}),
            'summary': data.get('summary', {}),
            'top_destinations': data.get('details', {}).get('top_destinations', [])[:10],
            'port_distribution': data.get('details', {}).get('port_distribution', {}),
            'protocol_breakdown': data.get('details', {}).get('protocol_breakdown', {}),
            'threat_classification': data.get('threat_classification'),
            'behavior_analysis': data.get('behavior_analysis', {})
        }
        return summary

    def _build_security_prompt(self, summary: Dict) -> str:
        """構建安全分析提示詞"""
        ip = summary['ip']
        ip_info = summary.get('ip_info')
        device_type = summary['device_type']
        time_range = summary.get('time_range', {})
        stats = summary['summary']
        ports = summary.get('port_distribution', {})
        protocols = summary.get('protocol_breakdown', {})
        top_dsts = summary.get('top_destinations', [])
        threat = summary.get('threat_classification')
        behaviors = summary.get('behavior_analysis', {}).get('behaviors', [])

        # 格式化埠號分佈（Top 10）
        top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
        ports_str = "\n".join([f"  - 埠 {port}: {count:,} 次連線" for port, count in top_ports])

        # 格式化協定分佈
        protocols_str = "\n".join([f"  - 協定 {proto}: {count:,} 次" for proto, count in protocols.items()])

        # 格式化 Top 目的地
        dsts_str = "\n".join([
            f"  - {dst['dst_ip']}: {dst['flow_count']:,} flows, {dst['total_bytes']:,} bytes"
            for dst in top_dsts
        ])

        # 構建 IP 資訊字串
        ip_info_str = ""
        if ip_info:
            if ip_info.get('is_public'):
                ip_info_str = f"""
**IP WHOIS 資訊**
- AS 號碼: AS{ip_info.get('asn', 'N/A')}
- AS 描述: {ip_info.get('asn_description', 'N/A')}
- AS CIDR: {ip_info.get('asn_cidr', 'N/A')}
- 國家代碼: {ip_info.get('asn_country_code', 'N/A')}
- 網路名稱: {ip_info.get('network_name', 'N/A')}
- 註冊機構: {ip_info.get('asn_registry', 'N/A')}"""
                if ip_info.get('org_name'):
                    ip_info_str += f"\n- 組織名稱: {ip_info.get('org_name')}"
            else:
                # 私有 IP - 包含設備映射資訊
                ip_info_str = f"\n**IP 類型**: {ip_info.get('type', '私有 IP')}"

                # 添加設備映射配置
                device_mapping = ip_info.get('device_mapping')
                if device_mapping and device_mapping.get('device_types'):
                    ip_info_str += "\n\n**內部網路設備 IP 範圍配置**\n"
                    for dev_type, dev_config in device_mapping['device_types'].items():
                        ip_info_str += f"\n{dev_type} ({dev_config.get('description', 'N/A')}):\n"
                        ip_ranges = dev_config.get('ip_ranges', [])
                        if ip_ranges:
                            ip_info_str += "  IP 範圍: " + ", ".join(ip_ranges) + "\n"
                        chars = dev_config.get('characteristics', [])
                        if chars:
                            ip_info_str += "  特徵: " + ", ".join(chars) + "\n"

        prompt = f"""請分析以下 IP 的網路流量數據，並提供安全評估報告。

**網路環境說明**
此網路環境屬於 TANet (Taiwan Academic Network，台灣學術網路) 的一部分。TANet 是台灣教育與研究機構使用的學術網路，連接全國各級學校與研究單位。請不要對 TANet 本身的架構或用途進行推測或說明，這是已知的網路環境。

**資料說明**
本報告提供的資料包含：
1. **NetFlow 流量分析**：從網路流量記錄中統計的通訊行為數據（流量數、封包數、位元組數、目的地 IP、埠分佈等）
2. **Isolation Forest 異常檢測**：使用機器學習模型（Isolation Forest）對流量特徵進行異常檢測，預判潛在風險
3. **威脅分類與置信度**：系統根據檢測到的行為特徵，自動分類威脅類型並估算置信度

**置信度 (Confidence) 說明**
置信度數值範圍為 0.0 ~ 1.0（或百分比 0% ~ 100%），表示系統對該威脅分類的確定程度：
- **計算方式**：基於多個流量特徵的加權評分（如埠數量、埠分散度、封包大小、流量模式等）
- **基礎置信度**：每種威脅類型從 0.6 (60%) 起始
- **特徵加成**：根據符合威脅特徵的程度累加（例如：掃描埠數 > 1000 可加 0.2；埠分散度 > 0.7 可加 0.15）
- **上限**：最高為 0.99 (99%)
- **意義解讀**：
  - 0.9+ (90%+)：高度確定，強烈符合該威脅模式
  - 0.7-0.9 (70%-90%)：較為確定，符合多項威脅特徵
  - 0.6-0.7 (60%-70%)：基礎判定，符合部分威脅特徵

請綜合考慮以上所有資訊，包含 IP 的角色（設備類型）、通訊行為統計、機器學習模型的異常檢測結果，重新評估風險並給予專業建議。

**基本資訊**
- IP 地址: {ip}
- 設備類型: {device_type}
- 分析時間範圍: {time_range.get('start', 'N/A')} 至 {time_range.get('end', 'N/A')} (共 {time_range.get('duration_minutes', 0)} 分鐘 / {time_range.get('duration_hours', 0):.1f} 小時)
{ip_info_str}

**流量統計**
- 總流量數: {stats.get('total_flows', 0):,}
- 總位元組: {stats.get('total_bytes', 0):,}
- 總封包數: {stats.get('total_packets', 0):,}
- 不重複目的地: {stats.get('unique_destinations', 0):,}
- 不重複目的埠: {stats.get('unique_dst_ports', 0):,}
- 不重複來源埠: {stats.get('unique_src_ports', 0):,}

**協定分佈**
{protocols_str if protocols_str else "  無數據"}

**重要說明：**
- ICMP 協定（協定編號 1）是網路層協定，用於網路診斷（如 ping）和錯誤報告
- ICMP 不使用埠號，因此 ICMP 流量的埠號為 0 是正常現象
- 如果看到大量埠號 0 的流量，請檢查協定分佈中是否有 ICMP，這可能是正常的網路診斷活動

**Top 目的埠號分佈**
{ports_str if ports_str else "  無數據"}
（注意：埠號 0 通常表示 ICMP 協定流量，這是正常現象）

**Top 通訊目的地**
{dsts_str if dsts_str else "  無數據"}
"""

        if behaviors:
            prompt += f"\n**檢測到的行為特徵**\n"
            for behavior in behaviors:
                prompt += f"- {behavior}\n"

        if threat:
            prompt += f"""
**威脅分類**
- 類型: {threat.get('class_name')} ({threat.get('class_name_en')})
- 嚴重性: {threat.get('severity')}
- 置信度: {threat.get('confidence', 0) * 100:.1f}%
- 描述: {threat.get('description')}
"""

        # 根據是否為公網 IP 決定分析要求
        is_public_ip = ip_info and ip_info.get('is_public', False)

        prompt += """

請根據以上數據提供：
1. **安全摘要** (2-3 句話總結主要發現)"""

        if is_public_ip:
            prompt += """
2. **IP 資訊分析** (根據提供的 WHOIS/AS 資訊，分析其安全意義，例如：該組織/ISP 的信譽度、是否為已知的雲服務商/CDN、是否有安全風險等)"""
        else:
            prompt += """
2. **設備類型分析** (根據提供的內部網路設備 IP 範圍配置，分析該 IP 所屬的設備類型及其正常行為模式)"""

        prompt += """
3. **關鍵觀察** (列出 3-5 個值得注意的流量特徵)
4. **IP 間互動推測** (根據 Top 通訊目的地和埠分佈，推測該 IP 與其他 IP 之間的互動行為模式，例如：是否為客戶端訪問服務、伺服器提供服務、P2P 通訊、或異常的掃描行為等)
5. **風險綜合評估** (綜合考慮以下因素重新評估風險：
   - Isolation Forest 異常檢測結果（如有提供威脅分類與置信度）
   - NetFlow 統計資料（流量模式、埠分佈、通訊對象）
   - IP 角色與設備類型的正常行為基準
   - 觀察到的異常行為特徵
   請說明是否同意系統的初步判斷，重新評估是否為系統誤判或是的確有值得注意的風險)
6. **建議措施** (基於上述綜合評估，提供 2-3 項具體的安全建議或調查方向)

請用清晰、專業的繁體中文回答，使用 Markdown 格式化。

**Markdown 格式要求：**
- 使用 `## 標題` 表示主要章節（如：## 1. 安全摘要）
- 使用 `### 小標題` 表示子章節
- 使用 `**重點文字**` 標記重要的專有名詞、數值、結論等
- 使用 `-` 或 `1.` 建立清單
- 關鍵發現、威脅名稱、IP位址、數值統計等務必使用 `**粗體**` 標記
- **標題和內文重點請使用不同的視覺呈現**：標題用於結構劃分，粗體用於內文中的關鍵資訊

**重要**: 請使用台灣用語，使用「埠」(port) 而不是「端口」，使用「伺服器」而不是「服務器」。
"""

        return prompt
