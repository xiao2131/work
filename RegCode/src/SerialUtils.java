

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;


/**
 * @Author By Yirs
 * @Date 2018-11-15 23:03:48
 * @Description 检测系统注册
 */
public class SerialUtils {

	static Integer StringUtifs;

	static {
		StringUtifs = 0;
	}

	public static Integer getStringUtifs() {
		return StringUtifs;
	}

	// 读取注册码
	public static String readContent(String path) {

		// 文件的路径
		String basePath = path.substring(0, path.length() - 1) + "/Reg/GTRCODE.txt";

		// 用来保存每次读取一行的内容
		String line = "";

		// 获得该文件的缓冲输入流
		BufferedReader bufferedReader = null;

		StringUtifs = 1;

		try {
			bufferedReader = new BufferedReader(new FileReader(new File(basePath)));

			// 只需要读取一行
			line = bufferedReader.readLine();

			if (line != null && line.length() > 1 && line != "") {

				String code[] = line.split(":");

				return code[1].toString();
			}

			return null;

		} catch (

		FileNotFoundException e1) {

			e1.printStackTrace();

			return "NoFound";

		} catch (IOException e) {

			e.printStackTrace();

			return "error";

		} finally {
			try {
				bufferedReader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

	// 校验格式 无错误返回correct
	@SuppressWarnings("unused")
	public static String checkFormat(String message) {

		if (message == null) {
			return null;
		} else if (message.equals("NoFound")) {

			return "注册信息已丢失，请重新注册！";

		} else if (message.equals("error")) {

			return "读取文件错误，请确保文件无损坏";

		} else if (message.length() != 172) {

			return "注册码格式错误";

		}

		return "correct";

	}

	// 未加密的注册码
	public static String getSequenceNumber(String code, Integer number, long time) throws IOException {

		Integer authNumber = number;

		return code + ":" + authNumber + ":" + time;

	}

	// 得到一年后的时间和永久时间的时间戳
	public static long getTimeLimit(String code) {

		Date date = new Date();

		Calendar cal = Calendar.getInstance();

		cal.setTime(date);

		if (code.toUpperCase().equals("Y")) {

			cal.add(Calendar.YEAR, 1);

		} else if (code.toUpperCase().equals("N")) {

			cal.add(Calendar.YEAR, 99);

		}

		return cal.getTimeInMillis();

	}

	// 根据注册码生成详细信息
	public static Result getInfo(String code) {

		String result = null;
		try {
			result = RSAUtils.decryptByPrivateKey(code);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

		String info[] = result.split(":");

		Result re = null;

		if (info.length == 3) {

			re = new Result();

			String serial = info[0];

			Integer number = Integer.valueOf(info[1]);

			long time = Long.parseLong(info[2]);

			re.setSerial(serial);

			re.setNumber(number);

			re.setTime(time);

		}

		return re;

	}

	public static String getOsType() {
		String osname = System.getProperty("os.name");

		if (osname.toLowerCase().contains("linux"))
			return "linux";
		if (osname.toLowerCase().contains("windows")) {
			return "windows";
		}
		return "unknown";
	}

	public static String getCpuId() {
		String result = "";
		if (getOsType().equals("windows")) {
			try {
				File file = File.createTempFile("tmp", ".vbs");
				file.deleteOnExit();
				FileWriter fw = new FileWriter(file);
				String vbs = "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\nSet colItems = objWMIService.ExecQuery _ \n   (\"Select * from Win32_Processor\") \nFor Each objItem in colItems \n    Wscript.Echo objItem.ProcessorId \n    exit for  ' do the first cpu only! \nNext \n";

				fw.write(vbs);
				fw.close();
				Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
				BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
				String line;
				while ((line = input.readLine()) != null) {
					result = result + line;
					result = getPwd(result);
				}
				input.close();
				file.delete();
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else if (getOsType().equals("linux")) {
			Runtime rt = Runtime.getRuntime();
			try {
				Process proc = rt.exec("dmidecode -t processor");
				InputStreamReader isr = new InputStreamReader(proc.getInputStream());
				BufferedReader br = new BufferedReader(isr);
				String line = null;
				boolean istest = false;
				while ((line = br.readLine()) != null) {
					if (line.toUpperCase().contains("Processor Information".toUpperCase())) {
						istest = true;
					}
					if ((istest) && (line.trim().toUpperCase().startsWith("ID:"))) {
						result = line.toUpperCase().trim().substring(3);
						result = getPwd(result);
						break;
					}
				}
				isr.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return result.trim();
	}

	// 将时间戳转换成字符串
	public static String getFormatTimeToString(long time) {

		Date date = new Date(time);

		SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		return simpleDateFormat.format(date);

	}

	// 将字符串装换成时间戳
	public static long getFormatTimeToLong(String time) {

		SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");

		try {

			return simpleDateFormat.parse(time).getTime();

		} catch (ParseException e) {

			e.printStackTrace();

		}

		return 0l;

	}

	// 写文件
	public static void mywrite(String path, String code) {

		// 文件的路径
		String basePath = path.substring(0, path.length() - 1) + "/Reg/GTRCODE.txt";

		File file = new File(basePath);

		OutputStream os = null;
		try {
			// 2、选择输出流,以追加形式(在原有内容上追加) 写出文件 必须为true 否则为覆盖
			os = new BufferedOutputStream(new FileOutputStream(file, false));
			String string = "code:" + code;
			byte[] data = string.getBytes(); // 将字符串转换为字节数组,方便下面写入

			os.write(data, 0, data.length); // 3、写入文件
			os.flush(); // 将存储在管道中的数据强制刷新出去
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.out.println("文件没有找到！");
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("写入文件失败！");
		} finally {
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					e.printStackTrace();
					System.out.println("关闭输出流失败！");
				}
			}
		}
	}

	// 写文件校验格式
	public static String inputCheckFormat(String code) {

		code = code.trim();

		if (code.length() != 172) {

			return "注册码格式错误!";

		}

		try {

			Result result = getInfo(code);

			if (result != null) {

				// 校验注册码
				if (!result.getSerial().equals(getSerial())) {
					return "请勿重复使用注册码";
				}
				// 校验日期
				if (getNetworkTime() >= result.getTime()) {
					return "注册码已过期";
				}

			} else {
				return "无效注册码";
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return "success";

	}

	// 获取网络时间
	public static long getNetworkTime() {
		try {
			URL url = new URL("http://www.baidu.com");
			URLConnection conn = url.openConnection();
			conn.connect();
			long dateL = conn.getDate();

			return dateL;
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return 0;

	}

	// md5加密
	public static String getPwd(String pwd) {
		try {
			// 创建加密对象
			MessageDigest digest = MessageDigest.getInstance("md5");

			// 调用加密对象的方法，加密的动作已经完成
			byte[] bs = digest.digest(pwd.getBytes());
			// 接下来，我们要对加密后的结果，进行优化，按照mysql的优化思路走
			// mysql的优化思路：
			// 第一步，将数据全部转换成正数：
			String hexString = "";
			for (byte b : bs) {
				// 第一步，将数据全部转换成正数：
				// 解释：为什么采用b&255
				/*
				 * b:它本来是一个byte类型的数据(1个字节) 255：是一个int类型的数据(4个字节)
				 * byte类型的数据与int类型的数据进行运算，会自动类型提升为int类型 eg: b: 1001 1100(原始数据) 运算时： b: 0000 0000
				 * 0000 0000 0000 0000 1001 1100 255: 0000 0000 0000 0000 0000 0000 1111 1111
				 * 结果：0000 0000 0000 0000 0000 0000 1001 1100 此时的temp是一个int类型的整数
				 */
				int temp = b & 255;
				// 第二步，将所有的数据转换成16进制的形式
				// 注意：转换的时候注意if正数>=0&&<16，那么如果使用Integer.toHexString()，可能会造成缺少位数
				// 因此，需要对temp进行判断
				if (temp < 16 && temp >= 0) {
					// 手动补上一个“0”
					hexString = hexString + "0" + Integer.toHexString(temp);
				} else {
					hexString = hexString + Integer.toHexString(temp);
				}
			}
			return hexString;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static String getSerial() {
		List codes = new ArrayList();

		List macList = getMacAddressList();
		String cpuId = getCpuId();
		String code = "";
		if ((macList != null) && (macList.size() > 0)) {
			for (int i = 0; i < macList.size(); i++) {
				code = getPwd((cpuId + (String) macList.get(i)).substring(8, 24).toUpperCase());
			}

		}

		return code;
	}

	public static List<String> getMacAddressList() {
		List addressList = new ArrayList();
		try {
			Enumeration el = NetworkInterface.getNetworkInterfaces();
			while (el.hasMoreElements()) {
				byte[] mac = ((NetworkInterface) el.nextElement()).getHardwareAddress();
				if (mac == null)
					continue;
				StringBuilder builder = new StringBuilder();
				for (byte b : mac) {
					builder.append(Integer.toHexString(b & 0xFF).toUpperCase());
					builder.append("-");
				}
				if (builder.length() > 0) {
					builder.deleteCharAt(builder.length() - 1);
				}

				addressList.add(builder.toString());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return addressList;
	}

}
