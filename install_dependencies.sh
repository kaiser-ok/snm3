#!/bin/bash
# Isolation Forest 依賴包安裝腳本

echo "======================================================================"
echo "Isolation Forest 依賴包安裝"
echo "======================================================================"
echo ""

# 檢查是否為 root
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  檢測到 root 權限"
    USE_SUDO=""
else
    USE_SUDO="sudo"
fi

echo "選擇安裝方式:"
echo "  1. 使用 apt (推薦，系統級安裝)"
echo "  2. 使用 pip (用戶級安裝)"
echo "  3. 使用 pip --break-system-packages (覆蓋系統限制)"
echo ""
read -p "請選擇 (1/2/3): " choice

case $choice in
    1)
        echo ""
        echo "======================================================================"
        echo "使用 apt 安裝系統包..."
        echo "======================================================================"
        echo ""

        echo "📦 安裝 numpy..."
        $USE_SUDO apt update
        $USE_SUDO apt install -y python3-numpy

        echo ""
        echo "📦 安裝 scikit-learn..."
        $USE_SUDO apt install -y python3-sklearn

        echo ""
        echo "📦 安裝 elasticsearch..."
        $USE_SUDO apt install -y python3-elasticsearch

        echo ""
        echo "======================================================================"
        echo "✅ apt 安裝完成"
        echo "======================================================================"
        ;;

    2)
        echo ""
        echo "======================================================================"
        echo "使用 pip 安裝 (用戶級)..."
        echo "======================================================================"
        echo ""

        echo "創建虛擬環境..."
        python3 -m venv venv

        echo "激活虛擬環境..."
        source venv/bin/activate

        echo "安裝依賴..."
        pip install numpy scikit-learn elasticsearch pyyaml

        echo ""
        echo "======================================================================"
        echo "✅ pip 安裝完成"
        echo "======================================================================"
        echo ""
        echo "⚠️  注意: 使用虛擬環境時，每次需要先執行:"
        echo "   source venv/bin/activate"
        echo ""
        ;;

    3)
        echo ""
        echo "======================================================================"
        echo "使用 pip --break-system-packages 安裝..."
        echo "======================================================================"
        echo ""

        echo "⚠️  警告: 這會覆蓋系統包管理限制"
        read -p "確定要繼續嗎？(y/N): " confirm

        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            pip3 install --break-system-packages numpy scikit-learn elasticsearch pyyaml

            echo ""
            echo "======================================================================"
            echo "✅ pip 安裝完成"
            echo "======================================================================"
        else
            echo "安裝已取消"
            exit 1
        fi
        ;;

    *)
        echo "無效選擇"
        exit 1
        ;;
esac

echo ""
echo "======================================================================"
echo "驗證安裝..."
echo "======================================================================"
echo ""

# 驗證
python3 << 'EOF'
import sys
packages = [
    ('numpy', 'NumPy'),
    ('sklearn', 'scikit-learn'),
    ('elasticsearch', 'Elasticsearch'),
    ('yaml', 'PyYAML')
]

all_ok = True
for module, name in packages:
    try:
        __import__(module)
        print(f"✅ {name} 安裝成功")
    except ImportError:
        print(f"❌ {name} 安裝失敗")
        all_ok = False

if all_ok:
    print("\n✅ 所有依賴已成功安裝！")
    print("\n下一步:")
    print("  python3 train_isolation_forest.py --days 1 --evaluate")
else:
    print("\n❌ 部分依賴安裝失敗，請檢查錯誤訊息")
    sys.exit(1)
EOF

exit_code=$?

echo ""
echo "======================================================================"

if [ $exit_code -eq 0 ]; then
    echo "✅ 安裝完成！可以開始訓練"
    echo "======================================================================"
    echo ""
    echo "快速開始:"
    echo "  1. 訓練模型:"
    echo "     python3 train_isolation_forest.py --days 1 --evaluate"
    echo ""
    echo "  2. 實時檢測:"
    echo "     python3 realtime_detection.py --minutes 10"
    echo ""
else
    echo "❌ 安裝未完成"
    echo "======================================================================"
fi
