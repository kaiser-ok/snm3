#!/usr/bin/env python3
"""
多 LLM 服務 - 支援 OpenAI 和 OpenRouter
用於 AI Beta 測試功能
"""
import time
import json
from typing import Dict, List, Optional
from config import Config


class MultiLLMService:
    """多 LLM 模型分析服務"""

    def __init__(self):
        """初始化多 LLM 服務"""
        self.openai_api_key = Config.OPENAI_API_KEY
        self.openrouter_api_key = Config.OPENROUTER_API_KEY
        self.openrouter_base_url = Config.OPENROUTER_API_BASE
        self.judge_model = Config.JUDGE_MODEL

    def analyze_with_multiple_models(
        self,
        model_ids: List[str],
        analysis_data: Dict,
        use_openrouter: bool = True
    ) -> Dict:
        """
        使用多個模型分析同一份數據

        Args:
            model_ids: 模型 ID 列表
            analysis_data: IP 分析數據
            use_openrouter: 是否使用 OpenRouter

        Returns:
            包含所有模型結果和最佳答案的字典
        """
        try:
            import openai
        except ImportError:
            return {
                'status': 'error',
                'error': '請安裝 openai 套件: pip install openai'
            }

        results = []
        prompt = self._build_security_prompt(analysis_data)

        # 並行分析所有模型
        for model_id in model_ids:
            try:
                start_time = time.time()

                # 決定使用哪個 API
                if use_openrouter and not model_id.startswith('gpt-'):
                    # 使用 OpenRouter
                    result = self._analyze_with_openrouter(model_id, prompt)
                else:
                    # 使用 OpenAI (直接或透過 OpenRouter)
                    if use_openrouter:
                        result = self._analyze_with_openrouter(model_id, prompt)
                    else:
                        result = self._analyze_with_openai(model_id, prompt)

                analysis_time = time.time() - start_time

                if result['status'] == 'success':
                    results.append({
                        'model_id': model_id,
                        'status': 'success',
                        'analysis': result['analysis'],
                        'tokens_used': result.get('tokens_used'),
                        'analysis_time': f'{analysis_time:.2f}s'
                    })
                else:
                    results.append({
                        'model_id': model_id,
                        'status': 'error',
                        'error': result.get('error', '未知錯誤'),
                        'analysis_time': f'{analysis_time:.2f}s'
                    })

            except Exception as e:
                results.append({
                    'model_id': model_id,
                    'status': 'error',
                    'error': f'分析失敗: {str(e)}'
                })

        # 使用 GPT-4o 評選最佳答案
        best_answer = None
        if len([r for r in results if r['status'] == 'success']) > 1:
            best_answer = self._judge_best_answer(results, prompt)

        return {
            'status': 'success',
            'results': results,
            'best_answer': best_answer,
            'total_models': len(model_ids),
            'successful_models': len([r for r in results if r['status'] == 'success'])
        }

    def _analyze_with_openai(self, model_id: str, prompt: str) -> Dict:
        """使用 OpenAI API 分析"""
        try:
            import openai

            client = openai.OpenAI(api_key=self.openai_api_key)

            response = client.chat.completions.create(
                model=model_id,
                messages=[
                    {
                        "role": "system",
                        "content": "你是一位網路安全專家，擅長分析 NetFlow 數據並識別潛在的安全威脅。請用繁體中文回答。"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )

            return {
                'status': 'success',
                'analysis': response.choices[0].message.content,
                'tokens_used': {
                    'prompt': response.usage.prompt_tokens,
                    'completion': response.usage.completion_tokens,
                    'total': response.usage.total_tokens
                }
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': f'OpenAI API 錯誤: {str(e)}'
            }

    def _analyze_with_openrouter(self, model_id: str, prompt: str) -> Dict:
        """使用 OpenRouter API 分析"""
        try:
            import openai

            client = openai.OpenAI(
                api_key=self.openrouter_api_key,
                base_url=self.openrouter_base_url
            )

            response = client.chat.completions.create(
                model=model_id,
                messages=[
                    {
                        "role": "system",
                        "content": "你是一位網路安全專家，擅長分析 NetFlow 數據並識別潛在的安全威脅。請用繁體中文回答。"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000,
                extra_headers={
                    "HTTP-Referer": Config.OPENROUTER_SITE_URL,
                    "X-Title": Config.OPENROUTER_APP_NAME
                }
            )

            return {
                'status': 'success',
                'analysis': response.choices[0].message.content,
                'tokens_used': {
                    'prompt': response.usage.prompt_tokens if response.usage else 0,
                    'completion': response.usage.completion_tokens if response.usage else 0,
                    'total': response.usage.total_tokens if response.usage else 0
                }
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': f'OpenRouter API 錯誤: {str(e)}'
            }

    def _judge_best_answer(self, results: List[Dict], original_prompt: str) -> Optional[Dict]:
        """使用 GPT-4o 評選最佳答案"""
        try:
            import openai

            # 只評估成功的結果
            successful_results = [r for r in results if r['status'] == 'success']
            if len(successful_results) < 2:
                return None

            # 構建評判提示詞
            judge_prompt = self._build_judge_prompt(successful_results, original_prompt)

            # 使用 OpenAI GPT-4o 進行評判
            client = openai.OpenAI(api_key=self.openai_api_key)

            response = client.chat.completions.create(
                model=self.judge_model,
                messages=[
                    {
                        "role": "system",
                        "content": "你是一位資深的網路安全專家和 AI 評審員。你的任務是評估多個 AI 模型對網路安全分析的回答質量，並選出最佳答案。"
                    },
                    {
                        "role": "user",
                        "content": judge_prompt
                    }
                ],
                temperature=0.2,
                max_tokens=1000,
                response_format={"type": "json_object"}
            )

            # 解析評判結果
            judgment = json.loads(response.choices[0].message.content)
            best_model_id = judgment.get('best_model_id')

            # 找到最佳答案
            best_result = next(
                (r for r in successful_results if r['model_id'] == best_model_id),
                None
            )

            if best_result:
                return {
                    'model_id': best_result['model_id'],
                    'analysis': best_result['analysis'],
                    'tokens_used': best_result.get('tokens_used'),
                    'score': judgment.get('score', 0),
                    'reason': judgment.get('reason', '未提供評選理由')
                }

            return None

        except Exception as e:
            print(f"評判失敗: {str(e)}")
            # 如果評判失敗，返回第一個成功的結果
            if successful_results:
                return {
                    'model_id': successful_results[0]['model_id'],
                    'analysis': successful_results[0]['analysis'],
                    'tokens_used': successful_results[0].get('tokens_used'),
                    'score': 0,
                    'reason': f'自動評判失敗，使用第一個成功的模型。錯誤: {str(e)}'
                }
            return None

    def _build_judge_prompt(self, results: List[Dict], original_prompt: str) -> str:
        """構建評判提示詞"""
        prompt = f"""請評估以下多個 AI 模型對網路安全分析問題的回答質量。

**原始問題摘要:**
{original_prompt[:500]}...

**各模型回答:**

"""
        for idx, result in enumerate(results, 1):
            model_name = result['model_id']
            analysis = result['analysis']
            prompt += f"""
### 模型 {idx}: {model_name}

{analysis}

---
"""

        prompt += """
請根據以下標準評估這些回答：

1. **準確性** (30分): 分析是否準確識別安全威脅，判斷是否合理
2. **深度** (25分): 分析是否深入，是否提供有價值的洞察
3. **完整性** (20分): 是否涵蓋所有重要方面（安全摘要、關鍵觀察、風險評估、建議措施等）
4. **可操作性** (15分): 建議是否具體可行
5. **專業性** (10分): 用語是否專業，表達是否清晰

請以 JSON 格式返回評估結果：

{
  "best_model_id": "最佳模型的完整 ID",
  "score": 85,
  "reason": "選擇理由（3-5 句話，說明為什麼這個答案最好）"
}

請確保返回有效的 JSON 格式。
"""
        return prompt

    def _build_security_prompt(self, data: Dict) -> str:
        """構建安全分析提示詞（複用 llm_service 的邏輯）"""
        from services.llm_service import LLMService

        llm_service = LLMService()
        summary = llm_service._prepare_analysis_summary(data)
        return llm_service._build_security_prompt(summary)
