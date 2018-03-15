import java.sql.*;  

class MysqlCon{  
	private Connection con;
	private PreparedStatement st;
	private ResultSet rs;
	private String publicKey;
	
	public MysqlCon() {
		try{  
			Class.forName("com.mysql.jdbc.Driver");  
			con=DriverManager.getConnection("jdbc:mysql://localhost:3306/AccountData","root","SECproject11");   
			
		}catch(Exception e){ System.out.println(e);}  
			
			}  
	
	
	public int getBalance(String pK) {
		int balance=-1;
		try {
			final String sql = "select * from Accounts where PublicKey= ?";
			st=con.prepareStatement(sql);  
			st.setString(1, pK);
			//st = con.createStatement();
			rs=st.executeQuery();
			while(rs.next())  {
				String publicKey = rs.getString("publicKey");
				balance = rs.getInt("Balance");
				System.out.println(" " + publicKey +" "+ balance);  
				
				//ønsker å returnere noe sånt som disse over da, men hvordan?
				}
		
			
			 	
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return balance; 
			
		
	}
	
	public void createPendingLedger(String sendingPK, String receivingPK, int amount) {
		try {
			//inserts a pending query that is for both of the parties (can be found by where x=123 or y=123)
			final String sql = "INSERT into Ledger_pending(PublicKey_sender, PublicKey_recevier, Amount) values (?, ?, ?)";
			st=con.prepareStatement(sql);  
			st.setString(1, sendingPK);
			st.setString(2, receivingPK);
			st.setInt(3, amount);
			st.executeUpdate();
			System.out.println("ok");  
			//how to ensure that an attacker does not execute this many times?? 
			
		}catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		
	}
	
	public void updateBalance(String PK_source, int current_balance) {
		try {
			rs=st.executeQuery("update Accounts set balance=current_balance where publicKey = PK_source;");
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	//must change from string to PublicKey in the input!
	public void getIncomingPendingTransfers(String publicKey) {
		final String sql_get_pending_tranfers= "select * from Ledger_pending where PublicKey_recevier=?";				
		try {
			st=con.prepareStatement(sql_get_pending_tranfers);
			st.setString(1, publicKey);
			rs=st.executeQuery();
			System.out.println(rs); 
			while(rs.next())  {
				String publicKey_sender = rs.getString("publicKey_sender");
				String publicKey_recevier = rs.getString("publicKey_recevier");
				int amount = rs.getInt("Amount");
				int transaction_id = rs.getInt("TransactionId");
				System.out.println(" " + publicKey_sender +" "+ " " + publicKey_recevier + " " + amount + " " + transaction_id);  
				
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  	
		
		//return (publicKey_sender + publicKey_recevier + " " + amount);	
	}
		
	
	
	public void createAcceptedLedger(String sendingPK, String receivingPK, int amount, int transactionID) {
		//also deletes the pending corresponding request 
		//Q: do we want to keep the transaction ID or create a new one? Here it keeps the old one
		final String sql = "INSERT into Ledger_accepted(PublicKey_sender, PublicKey_recevier, Amount, TransactionID) values (?, ?, ?, ?)";
		final String sql_delete = "delete from Ledger_pending where transactionID=?"; 
		
		try {
			con.setAutoCommit(false);
			st=con.prepareStatement(sql);  
			st.setString(1, sendingPK);
			st.setString(2, receivingPK);
			st.setInt(3, amount);
			st.setInt(4, transactionID);
			st.executeUpdate();
			System.out.println("Accepted Ledger updated");  
			
			st=con.prepareStatement(sql_delete);  
			st.setInt(1, transactionID);
			st.executeUpdate();
			con.commit();
			
			//either both or non of these things happen
		
		//denne skal kjøres inni receive_amount
		//har all info fra getIncomingPendingTransfers?
		//velger den man ønsker å godkjenne via transactionID, så sendes alt inn her
		//inserts that is for both of the parties (can be found by where x=123 or y=123)
		
		
			
		}catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		
	}
	
			}  

