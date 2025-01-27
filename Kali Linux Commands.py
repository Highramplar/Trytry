import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from difflib import SequenceMatcher
import json
import os
from typing import Dict, Any, List


class KaliCommandSearch:
    def __init__(self, root):
        self.root = root
        self.root.title("Kali Linux 命令搜索工具")

        # 设置窗口大小和位置
        window_width = 500
        window_height = 150
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # 创建主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建搜索框和按钮
        self.create_search_widgets()

        # 创建分类下拉菜单
        self.create_category_dropdown()

        # 加载命令数据
        self.load_commands()

        # 创建状态栏
        self.create_status_bar()

        # 绑定快捷键
        self.bind_shortcuts()

    def create_search_widgets(self):
        """创建搜索相关的部件"""
        search_frame = ttk.Frame(self.main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))

        search_label = ttk.Label(search_frame, text="搜索命令:")
        search_label.pack(side=tk.LEFT, padx=(0, 5))

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.fuzzy_var = tk.BooleanVar(value=True)
        self.fuzzy_check = ttk.Checkbutton(
            search_frame,
            text="模糊搜索",
            variable=self.fuzzy_var
        )
        self.fuzzy_check.pack(side=tk.LEFT, padx=5)

        self.search_button = ttk.Button(
            search_frame,
            text="搜索",
            command=self.search_command,
            style="Accent.TButton"
        )
        self.search_button.pack(side=tk.RIGHT)

    def create_category_dropdown(self):
        """创建分类下拉菜单"""
        category_frame = ttk.Frame(self.main_frame)
        category_frame.pack(fill=tk.X, pady=(0, 10))

        category_label = ttk.Label(category_frame, text="选择类别:")
        category_label.pack(side=tk.LEFT, padx=(0, 5))

        self.category_var = tk.StringVar(value="全部")
        categories = [
            "全部", "网络扫描", "无线工具", "漏洞利用", "密码工具",
            "取证工具", "Web工具", "数据库工具", "嗅探工具",
            "社会工程学", "逆向工程", "匿名工具"
        ]
        self.category_combo = ttk.Combobox(
            category_frame,
            textvariable=self.category_var,
            values=categories
        )
        self.category_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def similarity_score(self, str1: str, str2: str) -> float:
        """计算两个字符串的相似度"""
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()

    def fuzzy_search(self, search_term: str, text: str, threshold: float = 0.3) -> bool:
        """执行模糊搜索"""
        # 完全匹配
        if search_term in text.lower():
            return True

        # 分词匹配
        search_words = search_term.lower().split()
        text_words = text.lower().split()

        for search_word in search_words:
            word_match = False
            for text_word in text_words:
                if self.similarity_score(search_word, text_word) > threshold:
                    word_match = True
                    break
            if not word_match:
                return False
        return True

    def load_commands(self):
        """加载命令数据"""
        self.commands = {
            # === 网络扫描工具 ===
            'nmap': {
                '类别': '网络扫描',
                '描述': '强大的网络扫描和安全审计工具',
                '基本用法': 'nmap [选项] 目标',
                '常用选项': {
                    '-sS': 'TCP SYN 扫描（默认）',
                    '-sV': '版本检测',
                    '-p': '指定端口范围',
                    '-A': '启用操作系统检测和版本检测',
                    '-T4': '设置时序模板',
                    '-oN': '输出到文件'
                }
            },
            'masscan': {
                '类别': '网络扫描',
                '描述': '高速端口扫描器',
                '基本用法': 'masscan [选项] IP地址',
                '特点': {
                    '速度': '可以在6分钟内扫描整个互联网',
                    '异步': '支持异步扫描',
                    '可配置': '灵活的速率控制'
                }
            },
            'unicornscan': {
                '类别': '网络扫描',
                '描述': '信息收集和安全审计工具',
                '基本用法': 'unicornscan [选项] 目标',
                '特点': {
                    '异步': '支持异步扫描',
                    '协议': '支持TCP/UDP扫描',
                    '指纹': '操作系统指纹识别'
                }
            },

            # === 无线工具 ===
            'aircrack-ng': {
                '类别': '无线工具',
                '描述': '完整的无线网络安全审计套件',
                '组件': {
                    'airmon-ng': '配置监听模式',
                    'airodump-ng': '抓取数据包',
                    'aireplay-ng': '数据包注入',
                    'aircrack-ng': '破解密码'
                }
            },
            'kismet': {
                '类别': '无线工具',
                '描述': '无线网络检测和嗅探工具',
                '特点': {
                    '被动': '被动无线网络检测',
                    '支持': '支持多种无线协议',
                    'GPS': '支持GPS定位'
                }
            },
            'reaver': {
                '类别': '无线工具',
                '描述': 'WPS PIN码破解工具',
                '基本用法': 'reaver -i 接口 -b MAC地址 [选项]',
                '特点': {
                    'WPS': '专注于WPS漏洞利用',
                    '在线': '在线破解WPS PIN码',
                    '支持': '支持多种攻击模式'
                }
            },

            # === Web工具 ===
            'burpsuite': {
                '类别': 'Web工具',
                '描述': '专业的Web应用程序测试工具',
                '主要功能': {
                    'Proxy': '拦截和修改HTTP/HTTPS流量',
                    'Scanner': '自动化漏洞扫描',
                    'Intruder': '自动化渗透测试',
                    'Repeater': '手动请求测试'
                }
            },
            'nikto': {
                '类别': 'Web工具',
                '描述': 'Web服务器扫描器',
                '基本用法': 'nikto -h 目标',
                '特点': {
                    '全面': '检测多种漏洞类型',
                    '更新': '定期更新漏洞库',
                    '报告': '支持多种报告格式'
                }
            },
            'skipfish': {
                '类别': 'Web工具',
                '描述': '自动化Web安全扫描工具',
                '基本用法': 'skipfish [选项] -W 字典 -o 输出目录 目标URL',
                '特点': {
                    '递归': '递归扫描网站',
                    '智能': '自适应学习能力',
                    '报告': '生成详细报告'
                }
            },

            # === 漏洞利用工具 ===
            'metasploit': {
                '类别': '漏洞利用',
                '描述': '高级渗透测试平台',
                '组件': {
                    'msfconsole': '主控制台',
                    'msfvenom': '载荷生成器',
                    'msfdb': '数据库管理'
                }
            },
            'searchsploit': {
                '类别': '漏洞利用',
                '描述': 'Exploit-DB命令行搜索工具',
                '基本用法': 'searchsploit [搜索词]',
                '特点': {
                    '离线': '本地漏洞库搜索',
                    '更新': '定期更新漏洞库',
                    '导出': '支持多种导出格式'
                }
            },

            # === 密码工具 ===
            'hashcat': {
                '类别': '密码工具',
                '描述': '高级密码恢复工具',
                '基本用法': 'hashcat [选项] 哈希文件 字典文件',
                '特点': {
                    'GPU': '支持GPU加速',
                    '算法': '支持多种哈希算法',
                    '规则': '支持自定义规则'
                }
            },
            'john': {
                '类别': '密码工具',
                '描述': 'John the Ripper密码破解器',
                '基本用法': 'john [选项] 密码文件',
                '支持格式': [
                    'Unix密码哈希',
                    'Windows密码哈希',
                    '压缩文件密码',
                    '其他常见格式'
                ]
            },

            # === 取证工具 ===
            'autopsy': {
                '类别': '取证工具',
                '描述': '数字取证分析平台',
                '功能': {
                    '时间线': '创建文件活动时间线',
                    '恢复': '恢复删除的文件',
                    '搜索': '关键词搜索',
                    '报告': '生成取证报告'
                }
            },
            'foremost': {
                '类别': '取证工具',
                '描述': '文件恢复工具',
                '基本用法': 'foremost [选项] -i 镜像文件 -o 输出目录',
                '支持格式': [
                    'jpg', 'pdf', 'doc',
                    'zip', 'exe', 'mp4'
                ]
            },

            # === 数据库工具 ===
            'sqlmap': {
                '类别': '数据库工具',
                '描述': '自动化SQL注入工具',
                '基本用法': 'sqlmap -u 目标URL [选项]',
                '特点': {
                    '自动化': '自动检测和利用SQL注入',
                    '支持': '支持多种数据库',
                    '技术': '支持多种注入技术'
                }
            },
            'oscanner': {
                '类别': '数据库工具',
                '描述': 'Oracle数据库扫描器',
                '基本用法': 'oscanner -s 目标服务器 -P 端口',
                '功能': {
                    '扫描': '扫描Oracle漏洞',
                    '审计': '数据库配置审计',
                    '爆破': '密码爆破'
                }
            },

            # === 嗅探工具 ===
            'wireshark': {
                '类别': '嗅探工具',
                '描述': '网络协议分析器',
                '功能': {
                    '捕获': '实时数据包捕获',
                    '分析': '详细协议分析',
                    '过滤': '强大的过滤器',
                    '统计': '流量统计分析'
                }
            },
            'ettercap': {
                '类别': '嗅探工具',
                '描述': '中间人攻击工具',
                '基本用法': 'ettercap -G',
                '功能': {
                    'MITM': '中间人攻击',
                    '嗅探': '实时数据包嗅探',
                    '过滤': '数据包过滤和操作'
                }
            },

            # === 社会工程学 ===
            'set': {
                '类别': '社会工程学',
                '描述': 'Social-Engineer Toolkit',
                '功能': {
                    '钓鱼': '创建钓鱼攻击',
                    '克隆': '网站克隆',
                    '邮件': '批量邮件工具'
                }
            },
            'maltego': {
                '类别': '社会工程学',
                '描述': '开源情报收集工具',
                '功能': {
                    '可视化': '数据关系可视化',
                    '转换': '数据转换和关联',
                    '收集': '自动化信息收集'
                }
            },

            # === 逆向工程 ===
            'radare2': {
                '类别': '逆向工程',
                '描述': '逆向工程框架',
                '功能': {
                    '分析': '二进制分析',
                    '调试': '程序调试',
                    '反汇编': '代码反汇编',
                    '脚本': '脚本支持'
                }
            },
            'ghidra': {
                '类别': '逆向工程',
                '描述': 'NSA开源逆向工程工具',
                '功能': {
                    '反编译': '代码反编译',
                    '分析': '代码分析',
                    '协作': '团队协作功能',
                    'API': '脚本API支持'
                }
            },

            # === 匿名工具 ===
            'proxychains': {
                '类别': '匿名工具',
                '描述': '代理链工具',
                '基本用法': 'proxychains [命令]',
                '特点': {
                    '链式': '支持多级代理',
                    '协议': '支持多种代理协议',
                    '灵活': '可配置代理链'
                }
            },
            'macchanger': {
                '类别': '匿名工具',
                '描述': 'MAC地址修改工具',
                '基本用法': 'macchanger [选项] 网卡',
                '功能': {
                    '随机': '随机MAC地址',
                    '指定': '指定MAC地址',
                    '还原': '还原原始MAC'
                }
            },
            'anonsurf': {
                '类别': '匿名工具',
                '描述': '匿名化系统工具',
                '功能': {
                    'Tor': 'Tor网络集成',
                    'DNS': 'DNS匿名化',
                    'IP': 'IP匿名化'
                }
            }
        }

    def search_command(self):
        """执行搜索"""
        search_term = self.search_var.get().lower()
        selected_category = self.category_var.get()
        use_fuzzy = self.fuzzy_var.get()

        if not search_term:
            messagebox.showinfo("提示", "请输入搜索关键词")
            return

        self.status_var.set(f"正在搜索: {search_term}")
        results = []

        for cmd, info in self.commands.items():
            if selected_category != "全部" and info['类别'] != selected_category:
                continue

            # 搜索条件
            searchable_text = f"{cmd} {info['描述']} {info['类别']}"
            if use_fuzzy:
                if self.fuzzy_search(search_term, searchable_text):
                    results.append(self.format_command_info(cmd, info))
            else:
                if search_term in searchable_text.lower():
                    results.append(self.format_command_info(cmd, info))

        if results:
            self.show_results(results)
            self.status_var.set(f"找到 {len(results)} 个结果")
        else:
            messagebox.showinfo("提示", "未找到相关命令")
            self.status_var.set("未找到结果")

    def format_command_info(self, cmd: str, info: Dict[str, Any]) -> str:
        """格式化命令信息"""
        result = f"命令: {cmd}\n"
        result += f"类别: {info['类别']}\n"
        result += f"描述: {info['描述']}\n"

        # 添加基本用法（如果有）
        if '基本用法' in info:
            result += f"基本用法: {info['基本用法']}\n\n"

        # 添加常用选项（如果有）
        if '常用选项' in info:
            result += "常用选项:\n"
            for option, desc in info['常用选项'].items():
                result += f"  {option}: {desc}\n"
            result += "\n"

        # 添加主要功能（如果有）
        if '主要功能' in info:
            result += "主要功能:\n"
            for func, desc in info['主要功能'].items():
                result += f"  {func}: {desc}\n"
            result += "\n"

        # 添加特性（如果有）
        if '特性' in info:
            result += "特性:\n"
            for feature, desc in info['特性'].items():
                result += f"  {feature}: {desc}\n"
            result += "\n"

        # 添加示例（如果有）
        if '示例' in info:
            result += "使用示例:\n"
            for example in info['示例']:
                result += f"  {example}\n"

        return result

    def show_results(self, results: List[str]):
        """显示搜索结果"""
        result_window = tk.Toplevel(self.root)

    def show_results(self, results: List[str]):
        """显示搜索结果"""
        result_window = tk.Toplevel(self.root)
        result_window.title("搜索结果")
        result_window.geometry("800x600")

        # 创建主框架
        main_frame = ttk.Frame(result_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建工具栏
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        # 添加复制和保存按钮
        copy_button = ttk.Button(
            toolbar,
            text="复制全部",
            command=lambda: self.copy_to_clipboard(text_widget.get(1.0, tk.END))
        )
        copy_button.pack(side=tk.LEFT, padx=5)

        save_button = ttk.Button(
            toolbar,
            text="保存到文件",
            command=lambda: self.save_to_file(text_widget.get(1.0, tk.END))
        )
        save_button.pack(side=tk.LEFT, padx=5)

        # 创建搜索结果文本框
        text_widget = scrolledtext.ScrolledText(
            main_frame,
            wrap=tk.WORD,
            width=80,
            height=30,
            font=('Courier', 10)
        )
        text_widget.pack(fill=tk.BOTH, expand=True)

        # 插入结果
        for i, result in enumerate(results, 1):
            text_widget.insert(tk.END, f"结果 {i}:\n")
            text_widget.insert(tk.END, result)
            text_widget.insert(tk.END, "\n" + "="*80 + "\n\n")

        # 使文本只读
        text_widget.config(state=tk.DISABLED)

        # 添加快捷键
        result_window.bind('<Control-c>', lambda e: self.copy_to_clipboard(text_widget.get(1.0, tk.END)))
        result_window.bind('<Control-s>', lambda e: self.save_to_file(text_widget.get(1.0, tk.END)))

    def copy_to_clipboard(self, text: str):
        """复制文本到剪贴板"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("已复制到剪贴板")

    def save_to_file(self, text: str):
        """保存结果到文件"""
        try:
            file_path = tk.filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="保存搜索结果"
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(text)
                self.status_var.set(f"已保存到: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存文件时出错: {str(e)}")

    def create_status_bar(self):
        """创建状态栏"""
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("就绪")

    def bind_shortcuts(self):
        """绑定快捷键"""
        self.root.bind('<Control-f>', lambda e: self.search_entry.focus())
        self.search_entry.bind('<Return>', lambda e: self.search_command())
        self.root.bind('<Escape>', lambda e: self.root.attributes('-topmost', False))
        self.root.bind('<Control-q>', lambda e: self.root.quit())

def main():
    """主函数"""
    try:
        # 创建主窗口
        root = tk.Tk()
        root.title("Kali Linux 命令搜索工具")

        # 设置窗口图标（如果有的话）
        try:
            root.iconbitmap('kali.ico')
        except:
            pass

        # 设置主题样式
        style = ttk.Style()
        style.configure("Accent.TButton", foreground="blue")

        # 创建应用实例
        app = KaliCommandSearch(root)

        # 启动主循环
        root.mainloop()

    except Exception as e:
        messagebox.showerror("错误", f"程序启动失败: {str(e)}")

if __name__ == "__main__":
    main()