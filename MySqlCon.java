import java.sql.*;
import java.util.ArrayList;
import java.util.List;  

class MysqlCon{  
	private Connection con;
	private PreparedStatement st;
	private ResultSet rs;
	
	
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
			rs=st.executeQuery();
			while(rs.next())  {
				String publicKey = rs.getString("publicKey");
				balance = rs.getInt("Balance");
				System.out.println(" " + publicKey +" "+ balance);  
				
				}
		
			
			 	
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return balance; 
			
		
	}
	
	public void addNonce(String PublicKey, String Nonce) { //kjører bare dersom den ikke finnes der fra før av
		
		final String sql = "insert into Nonces(Nonce, PublicKey_sender) values (?, ?)";
		
		
		try {
			st=con.prepareStatement(sql);
			st.setString(1, Nonce);
			st.setString(2, PublicKey);
			st.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	public boolean checkNonce(String nonce, String PK) {
		Boolean result = false;
		final String sql = "select ? from Nonce where PublicKey_sender= ?";
	
		
		
		try {
			st=con.prepareStatement(sql);
			st.setString(1, nonce);
			st.setString(2, PK);
			rs=st.executeQuery();
			if(rs.next())  {
				result = true;
			}
			
		
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
		
	}
	
	public void createPendingTransaction(String sendingPK, String receivingPK, int amount) {
		try {
			//inserts a pending query that is for both of the parties (can be found by where x=123 or y=123)
			final String sql = "INSERT into Ledger(PublicKey_sender, PublicKey_recevier, Amount, status) values (?, ?, ?,?)";
			st=con.prepareStatement(sql);  
			st.setString(1, sendingPK);
			st.setString(2, receivingPK);
			st.setInt(3, amount);
			st.setString(4, "pending");
			st.executeUpdate();
			System.out.println("ok");  
			//how to ensure that an attacker does not execute this many times?? 
			
		}catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		
	}
	
	public void createBalance(String PK, int initial_value) {
		try {
			final String sql="insert into Accounts(PublicKey, Balance) values (?, ?)";
			st=con.prepareStatement(sql);
			st.setInt(2, initial_value);
			st.setString(1, PK);
			st.executeUpdate();
		}
		catch(SQLException e){
			e.printStackTrace();
		}
		
	}
	
	
	public void CreatePendingLedgerAndUpdateBalance(String PK_source, String PK_destination, int amount, int current_balance) {
		
		String sql = "update Accounts set Balance=? where PublicKey=?";
		final String sql_l = "INSERT into Ledger(PublicKey_sender, PublicKey_recevier, Amount, status) values (?, ?, ?,?)";
		//merge two methods in order to ensure that either both or none of them happen. 
		try {
			con.setAutoCommit(false);
			st=con.prepareStatement(sql);
			st.setInt(1, current_balance);
			st.setString(2, PK_source );
			st.executeUpdate();
			
			st=con.prepareStatement(sql_l);  
			st.setString(1, PK_source);
			st.setString(2, PK_destination);
			st.setInt(3, amount);
			st.setString(4, "pending");
			st.executeUpdate();
			con.commit();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void updateBalance(String PK_source, int current_balance) {
		try {
			String sql = "update Accounts set Balance=? where PublicKey=?";
			st=con.prepareStatement(sql);
			st.setInt(1, current_balance);
			st.setString(2, PK_source );
			st.executeUpdate();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	public List<String> getIncomingPendingTransfers(String publicKey) {
		List<String> outputList = new ArrayList<>();
		final String sql_get_pending_tranfers= "select * from Ledger where PublicKey_recevier=? and status=pending";				
		try {
			st=con.prepareStatement(sql_get_pending_tranfers);
			st.setString(1, publicKey);
			rs=st.executeQuery();
			System.out.println(rs); 
			while(rs.next())  {
				String src = rs.getString("publicKey_sender");
				String dst = rs.getString("publicKey_recevier");
				int amount = rs.getInt("Amount");
				int transaction_id = rs.getInt("TransactionId");
				String output = "Sender: " + src + ", Amount: " + amount + ", Transaction ID: " + transaction_id; 
				outputList.add(output);
				
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		return outputList;
		
		//return (publicKey_sender + publicKey_recevier + " " + amount);	
	}
	
	public List<String> getAllTransfers(String publicKey) {
		List<String> transfers = new ArrayList<String>();
		final String sql="Select * from Ledger where PublicKey_receiver=? or PublicKey_sender=?";
		try {
			st=con.prepareStatement(sql);
			st.setString(1, publicKey);
			st.setString(2, publicKey);
			st.executeUpdate();
			while(rs.next())  { 
				String publicKey_sender = rs.getString("publicKey_sender");
				String publicKey_recevier = rs.getString("publicKey_recevier");
				int amount = rs.getInt("Amount");
				int transaction_id = rs.getInt("TransactionId");
				String transfer = "Sender: " + publicKey_sender + ", Receiver: " + publicKey_recevier+ ", Amount: " + amount + ", Transaction ID: " + transaction_id; 
				transfers.add(transfer);
		
			}
			} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		
		
	
		return transfers;
	}
	
	public void AcceptTransactionAndUpdateBalance(String receivingPK, int transactionID) {
		
		final String sql = "update Ledger set status='accepted'"
				+ " where TransactionID=? and PublicKey_recevier=?";
		
		final String sql3 = "select amount from Ledger where TransactionID=? and PublicKey_recevier=?";
		
		final String sql2 = "Update Accounts set balance = balance+? where PublicKey=?";
		int amount = -1;
		try {
			con.setAutoCommit(false);
			
			st=con.prepareStatement(sql);  
			//st.setString(1, sendingPK);
			st.setString(2, receivingPK);
			//st.setInt(3, amount);
			st.setInt(1, transactionID);
			st.executeUpdate();
			System.out.println("Transaction accepted");  
			
			st=con.prepareStatement(sql3);
			st.setInt(1, transactionID);
			st.setString(2, receivingPK);
			rs=st.executeQuery(); //this is the amount that will be added to the account of the receiver
			while(rs.next())  {
				amount = rs.getInt("Amount");
			
			}
			
			st=con.prepareStatement(sql2);
			if (amount!=-1) {
				st.setInt(1, amount); 		 
			}
			
			st.setString(2, receivingPK);
			st.executeUpdate(); //this is the amount that will be added to the account of the receiver
			System.out.println("Money transferred"); 
			con.commit(); //either all or non of these things happen
		
		
		}catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		
	}
	
			}  


