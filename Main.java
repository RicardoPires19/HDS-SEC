
public class Main {
	
	public static void main(String[] args) {
		MysqlCon connect = new MysqlCon();
		//connect.getBalance("1234");
		connect.getIncomingPendingTransfers("221");
	}

}
