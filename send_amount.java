import java.sql.SQLException;
import java.sql.*;
//!!!Security not implemented
public class send_amount {
	
	MysqlCon connect = new MysqlCon();
	int current_balance;
	
	public send_amount(String PK_source, String PK_destination, int amount) throws SQLException {
		
		int current_balance = connect.getBalance(PK_source); 
		
		if ((current_balance-amount)>=0) {
			//server says yes it is, then authentication is required
			//if //if PK_source matches the private key --need to check that first
			
				current_balance-=amount; 
			
				//updates Balance and creates pending request
				//connect.updateCreatePendingLedgerAndUpdateBalance(PK_source, PK_destination, (int) amount, current_balance);
				//send ack to client
		}else {
				//send message to client saying that it is not possible due to too low balance
				
			
		}
	}

}
