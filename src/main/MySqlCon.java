package main;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;  

class MysqlCon{  
	private Connection con = null;
	private PreparedStatement st;
	private ResultSet rs;


	public MysqlCon() {
		try{  
			Class.forName("com.mysql.jdbc.Driver").newInstance();
			con=DriverManager.getConnection("jdbc:mysql://localhost/AccountData?"
                            + "user=root&password=root");
			con.prepareStatement("CREATE TABLE IF NOT EXISTS Accounts(PublicKey VARCHAR(500) NOT NULL, Balance INT NOT NULL)").executeUpdate();
			con.prepareStatement("CREATE TABLE IF NOT EXISTS Nonces(Nonce VARCHAR(500) NOT NULL, PublicKey_sender VARCHAR(500) NOT NULL)").executeUpdate();
			con.prepareStatement(
					"CREATE TABLE IF NOT EXISTS Ledgers("
					+ "ID INT AUTO_INCREMENT primary key NOT NULL, "
					+ "PublicKey_sender VARCHAR(500) NOT NULL, "
					+ "PublicKey_receiver VARCHAR(500) NOT NULL, "
					+ "Amount INT NOT NULL, "
					+ "Status VARCHAR(30) NOT NULL, "
					+ "Signatures VARCHAR(500) NOT NULL)").executeUpdate();
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
//				String publicKey = rs.getString("publicKey");
				balance = rs.getInt("Balance");
				//System.out.println(" GET BALANCE FROM: " + publicKey +" Result: "+ balance);  
			}



		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return balance; 


	}

	public boolean checkClient(String pk) {
		boolean returning=false;
		final String sql = "select * from Accounts where PublicKey= ?";
		try {
			st=con.prepareStatement(sql);
			st.setString(1, pk);
			rs=st.executeQuery();
			if(rs.next())  {
				returning= true;
			}

		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return returning;
	}

	public void addNonce(String PublicKey, String Nonce) {

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
		final String sql = "select * from Nonces where publicKey_sender= ? and nonce = ?";
		System.out.println("checkNonce: nonce:"+nonce+" key:"+PK);

		try {
			st=con.prepareStatement(sql);
			st.setString(1, PK);
			st.setString(2, nonce);
			rs=st.executeQuery();
			if(rs.next())  {
				System.out.println(rs.getString("nonce"));
				result = true;
			}
			


		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println("nonce: " + nonce);
			System.out.println("PK: " +PK);
			System.out.println("Exception: " + e);
		}
		return result;

	}

	public void createPendingTransaction(String sendingPK, String receivingPK, int amount, String signature) {
		try {
			//inserts a pending query that is for both of the parties (can be found by where x=123 or y=123)
			final String sql = "INSERT into Ledgers(PublicKey_sender, PublicKey_receiver, Amount, status, Signature) values (?, ?, ?, ?, ?)";
			st=con.prepareStatement(sql);  
			st.setString(1, sendingPK);
			st.setString(2, receivingPK);
			st.setInt(3, amount);
			st.setString(4, "pending");
			st.setString(5, signature);
			st.executeUpdate();
			//how to ensure that an attacker does not execute this many times?? 

		}catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  

	}

	public void AddClient(String PK, int initial_value) {
		try {
			final String sql="insert into Accounts(PublicKey, Balance) values (?, ?)";
			st=con.prepareStatement(sql);
			st.setInt(2, initial_value);
			st.setString(1, PK);
			st.executeUpdate();
		}
		catch(SQLException e){
			e.printStackTrace();
		} catch(Exception e){
			System.out.println("PK: " + PK);
			System.out.println("value: " + initial_value);
		}

	}


	public void CreatePendingLedgerAndUpdateBalance(String PK_source, String PK_destination, int amount, int current_balance, String signature) {

		String sql = "update Accounts set Balance=? where PublicKey=?";
		final String sql_l = "INSERT into Ledgers(PublicKey_sender, PublicKey_receiver, Amount, status, Signature) values (?, ?, ?, ?, ?)";
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
			st.setString(5, signature);
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
		final String sql_get_pending_tranfers= "select * from Ledgers where PublicKey_receiver=? and status='pending'";				
		try {
			st=con.prepareStatement(sql_get_pending_tranfers);
			st.setString(1, publicKey);
			rs=st.executeQuery();
			while(rs.next())  {
				String src = rs.getString("publicKey_sender");
//				String dst = rs.getString("publicKey_receiver");
				int amount = rs.getInt("Amount");
				String output = "SENDER: " + src + "\n AMOUNT: " + amount ;
				outputList.add(output);

			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		return outputList;

		//return (publicKey_sender + publicKey_receiver + " " + amount);	
	}

	public List<String> getAllTransfers(String publicKey) {
		List<String> transfers = new ArrayList<String>();
		final String sql="Select * from Ledgers where publickey_sender = ?";
		try {
			st=con.prepareStatement(sql);
			st.setString(1, publicKey);
			//st.setString(2, publicKey);
			rs= st.executeQuery();
			while(rs.next())  { 
				System.out.println("fdd");
				String publicKey_sender = rs.getString("publicKey_sender");
				String publicKey_receiver = rs.getString("publicKey_receiver");
				int amount = rs.getInt("Amount");
				String transfer = "Sender: " + publicKey_sender + ", Receiver: " + publicKey_receiver+ ", Amount: " + amount;
				transfers.add(transfer);

			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		return transfers;
	}
	
	public List<String> pedingTransactionsList(String pubKey){
		List<String> transfers = new ArrayList<String>();
		final String sql = "SELECT * FROM Ledgers WHERE PublicKey_receiver= ? and status='pending'";
		try {
			st=con.prepareStatement(sql);
			st.setString(1, pubKey);
			rs= st.executeQuery();
			while(rs.next())  { 
				int id = rs.getInt("ID");
				String publicKey_sender = rs.getString("publicKey_sender");
				int amount = rs.getInt("Amount");
				String transfer = "ID:"+id +" Sender:" + publicKey_sender + " Amount: " + amount; 
				transfers.add(transfer);

			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
		return transfers;
	}

	public void AcceptTransactionAndUpdateBalance(String pubKey,int transactionID) {

		final String sql = "update Ledgers set status='accepted'"
				+ " where ID= ?";

		final String sql3 = "select amount from Ledgers where ID=?";

		final String sql2 = "Update Accounts set Balance = Balance+? where PublicKey=?";
		int amount = -1;
		try {
			con.setAutoCommit(false);

			st=con.prepareStatement(sql);
			st.setInt(1, transactionID);
			st.executeUpdate();
			System.out.println("Transaction accepted");  

			st=con.prepareStatement(sql3);
			st.setInt(1, transactionID);
			rs=st.executeQuery(); //this is the amount that will be added to the account of the receiver
			while(rs.next())  {
				amount = rs.getInt("Amount");

			}

			st=con.prepareStatement(sql2);
			if (amount!=-1) {
				st.setInt(1, amount); 		 
			}

			st.setString(2, pubKey);
			st.executeUpdate(); //this is the amount that will be added to the account of the receiver
			System.out.println("Money transferred"); 
			con.commit(); //either all or non of these things happen


		}catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  

	}


	public List<String> getAllPublicKeys() throws SQLException {
		final String sql = "SELECT PublicKey FROM Accounts";
		st=con.prepareStatement(sql);
		rs=st.executeQuery();
		List<String> resultList = new ArrayList<String>();
		while(rs.next())  {
			resultList.add(rs.getString(1));
		}
		return resultList;
	}

}  

