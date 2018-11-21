

import java.io.IOException;
import java.util.Scanner;



public class Demo {
	public static void main(String[] args) throws Exception {

		System.out.println("------注册码计算器-------");

		System.out.println("----输入1进入自动模式----");

		System.out.println("----输入2进入手动模式----");

		System.out.println("-------------------------");

		System.out.println("----您当前的机器码为----");

		System.out.println(SerialUtils.getSerial());

		Scanner scanner = new Scanner(System.in);

		Integer state = scanner.nextInt();

		if (state == 1) {

			while (true) {

				System.out.println("请输入机器码");

				String code = scanner.next();

				System.out.println("请输入授权数量");

				Integer number = scanner.nextInt();

				System.out.println("按Y为一年，按N为永久期限");

				String str = scanner.next();

				if (str.toUpperCase().equals("Y") || str.toUpperCase().equals("N")) {

					long time = SerialUtils.getTimeLimit(str);

					String serial = SerialUtils.getSequenceNumber(code, number, time);

					System.out.println(RSAUtils.encryptByPublicKey(serial));		
					
					System.out.println("请输入任意字母结束");
					
					scanner.next();					

					break;
					
					
					
				} else {

					System.out.println("请勿输入其他字母");

					continue;

				}

			}

		}

		if (state == 2) {

			while (true) {

				System.out.println("请输入机器码");

				String code = scanner.next();

				System.out.println("请输入授权数量");

				Integer number = scanner.nextInt();

				System.out.println("请输入有效期（格式：2018-11-16）");

				String time = scanner.next();

				String serial = SerialUtils.getSequenceNumber(code, number, SerialUtils.getFormatTimeToLong(time));

				System.out.println(RSAUtils.encryptByPublicKey(serial));
				
				System.out.println("请输入任意字母结束");
				
				scanner.next();					

				break;

			}

		}

	}

}
