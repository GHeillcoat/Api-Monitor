import sys
from PyQt5.QtWidgets import QApplication
from ui.main_window import MainWindow
from core.logger import logger

def main():
    # 初始化日志
    logger.info("启动API Monitor...")
    
    # 创建Qt应用
    app = QApplication(sys.argv)
    
    # 创建并显示主窗口
    window = MainWindow()
    window.show()
    
    # 运行应用
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()