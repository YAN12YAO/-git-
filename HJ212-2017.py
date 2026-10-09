class HJ212Parser:
    """
    HJ 212-2017 污染物在线监控(监测)系统数据传输协议报文解析器
    支持报文格式合法性校验、ANSI CRC16校验、数据段结构化解析、监测因子数据提取
    """

    def __init__(self):
        pass

    def _crc16(self, data: bytes) -> int:
        """
        私有方法：实现ANSI CRC16循环冗余校验算法
        严格遵循HJ212-2017附录A规范：初始值0xFFFF，多项式0xA001

        Args:
            data: 待校验的字节流

        Returns:
            int: 16位CRC校验结果整数
        """
        crc_reg = 0xFFFF
        for byte in data:
            # 每字节先与CRC寄存器高8位异或
            crc_reg = (crc_reg >> 8) ^ byte
            # 逐位处理8个比特位
            for _ in range(8):
                check_bit = crc_reg & 0x0001
                crc_reg >>= 1
                if check_bit:
                    crc_reg ^= 0xA001
        return crc_reg

    def _to_str(self, message) -> str:
        """私有方法：统一将输入报文转换为UTF-8字符串，兼容bytes和str输入"""
        if isinstance(message, bytes):
            try:
                return message.decode('utf-8')
            except UnicodeDecodeError:
                return ''
        return str(message)

    def is_valid_message(self, message) -> bool:
        """
        检查报文格式是否符合HJ212-2017规范
        标准报文结构：## + 4位十进制长度 + 数据段 + 4位十六进制CRC + \r\n

        Args:
            message: 待检查的报文（支持str或bytes类型）

        Returns:
            bool: 格式合法返回True，否则返回False
        """
        msg = self._to_str(message)
        # 校验包头、包尾
        if not msg.startswith('##') or not msg.endswith('\r\n'):
            return False
        # 最小长度校验：包头(2)+长度域(4)+数据段(最小0)+CRC(4)+包尾(2) = 12
        if len(msg) < 12:
            return False
        # 校验长度域（必须为4位十进制数字）
        length_str = msg[2:6]
        if not length_str.isdigit():
            return False
        data_len = int(length_str)
        # 校验总长度是否与长度域声明一致
        expected_total_length = 2 + 4 + data_len + 4 + 2
        if len(msg) != expected_total_length:
            return False
        # 校验CRC域格式（必须为4位十六进制字符）
        crc_str = msg[6 + data_len: 6 + data_len + 4]
        if len(crc_str) != 4:
            return False
        try:
            int(crc_str, 16)
        except ValueError:
            return False
        return True

    def validate_crc(self, message) -> bool:
        """
        校验报文的CRC16校验值是否正确

        Args:
            message: 待校验的报文（支持str或bytes类型）

        Returns:
            bool: CRC校验通过返回True，否则返回False
        """
        if not self.is_valid_message(message):
            return False
        msg = self._to_str(message)
        data_len = int(msg[2:6])
        # 提取数据段
        data_segment = msg[6: 6 + data_len]
        # 提取报文中的CRC值（统一转大写）
        received_crc = msg[6 + data_len: 6 + data_len + 4].upper()
        # 计算数据段的CRC值
        calculated_crc = self._crc16(data_segment.encode('utf-8'))
        calculated_crc_str = f"{calculated_crc:04X}"
        return received_crc == calculated_crc_str

    def parse_data_segment(self, message) -> dict:
        """
        解析报文数据段，返回结构化的键值对字典
        外层字段直接展开，CP数据区会解析为嵌套字典

        Args:
            message: 待解析的报文（支持str或bytes类型）

        Returns:
            dict: 解析后的数据段字段，其中'CP'键对应内部数据区的字典

        Raises:
            ValueError: 报文格式不合法时抛出
        """
        if not self.is_valid_message(message):
            raise ValueError("报文格式不符合HJ212-2017规范")
        msg = self._to_str(message)
        data_len = int(msg[2:6])
        data_segment = msg[6: 6 + data_len]

        # 解析外层字段
        fields = {}
        items = data_segment.split(';')
        for item in items:
            item = item.strip()
            if not item or '=' not in item:
                continue
            key, value = item.split('=', 1)
            fields[key] = value

        # 解析CP内部数据区（去除前后&&包裹符）
        if 'CP' in fields:
            cp_raw = fields['CP']
            if cp_raw.startswith('&&') and cp_raw.endswith('&&'):
                cp_content = cp_raw[2:-2]
            else:
                cp_content = cp_raw.strip('&')
            cp_fields = {}
            if cp_content:
                cp_items = cp_content.split(';')
                for cp_item in cp_items:
                    cp_item = cp_item.strip()
                    if not cp_item or '=' not in cp_item:
                        continue
                    cp_key, cp_val = cp_item.split('=', 1)
                    cp_fields[cp_key] = cp_val
            fields['CP'] = cp_fields

        return fields

    def extract_monitoring_data(self, message) -> dict:
        """
        从CP数据区中提取所有监测因子及其数值
        覆盖水污染物、气污染物、工况参数、设备状态、声环境等各类监测项
        匹配规则：键名包含'-'（符合xxxxxx-xxx的标准命名规范）

        Args:
            message: 待解析的报文（支持str或bytes类型）

        Returns:
            dict: 键为监测因子项（如w01001-Rtd），值为对应数值
        """
        try:
            parsed = self.parse_data_segment(message)
        except ValueError:
            return {}
        cp_data = parsed.get('CP', {})
        # 提取所有带分隔符的监测因子项
        monitoring_data = {
            key: value
            for key, value in cp_data.items()
            if '-' in key
        }
        return monitoring_data
