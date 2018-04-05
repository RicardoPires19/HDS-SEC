import java.util.Scanner;

public class receive_amount {
	
	MysqlCon connect = new MysqlCon();
	
	public receive_amount(String publicKey) {
		connect.getIncomingPendingTransfers(publicKey); //this is the receiver
		
		Scanner reader = new Scanner(System.in);  // Reading from System.in
		System.out.println("Select which transaction you would like to accept by typing in the corresponding transaction ID : ");
		int transaction_id = reader.nextInt();
		connect.AcceptTransactionAndUpdateBalance(publicKey, transaction_id);
		//send ack to the client if successful
		
	}
	
	//først finne (med select) den transactionen som skal godkjennes (bruker velger dette med user input (velger et tall liksom)) 
			//where transactio. dette gjøres da i receive amount

}
