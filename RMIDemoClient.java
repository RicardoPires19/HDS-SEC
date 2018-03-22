
import java.rmi.Naming;
import java.rmi.RemoteException;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JLabel;

public class RMIDemoClient {
	
	public static String userKey;
	public static RMIDemo rMIDemo;
	
	public static void main(String[] args) throws Exception{
		if (args.length == 1) {
			String url = new String("rmi://"+args[0]+"/RMIDemo");
			rMIDemo = (RMIDemo)Naming.lookup(url);
			
			registerMenu();
		}else {
			System.err.println("Usage: RMIDemoClient <server>");
		}
	}
	
	public static void registerMenu() throws RemoteException{
		JLabel label_key = new JLabel("Dgive Key:");
		JTextField key = new JTextField();
		 
		String serverReply="";
		
		Object[] array = {label_key,  key};
		 
		int res = JOptionPane.showConfirmDialog(null, array, "Register", 
		        JOptionPane.OK_CANCEL_OPTION,
		        JOptionPane.PLAIN_MESSAGE);
		
		if (res == JOptionPane.OK_OPTION) {
			userKey = key.getText().trim();
			serverReply = rMIDemo.register(userKey);
			mainMenu(serverReply);
		}
		else{
			goodbyeMenu();
		}
	}
	
	public static void mainMenu(String serverReply) throws NumberFormatException, RemoteException{
		
			Object[] options = {"Check Account", "Send Amount","Receive Amount", "Audit", "Logout"};
			int res = JOptionPane.showOptionDialog(null, serverReply,
				    "HDS Coin",
				    JOptionPane.YES_NO_OPTION,
				    JOptionPane.QUESTION_MESSAGE,
				    null,     //do not use a custom Icon
				    options,  //the titles of buttons
				    options[0]);
			switch(res){
				case 0: checkAccountMenu();
						return;
				
				case 1:	sendAmountMenu();
						return;
			
				case 2: receiveAmountMenu();
						return;
				
				case 3: auditMenu();
						return;
				
				case 4: registerMenu();
						return;
				
				default:goodbyeMenu();
						return;
				
			}
	}

	public static void checkAccountMenu() throws RemoteException{
		String serverReply = rMIDemo.check_account(userKey).toString();
		int res = JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
		        JOptionPane.CANCEL_OPTION,
		        JOptionPane.INFORMATION_MESSAGE);
			if(res == JOptionPane.OK_OPTION){
				mainMenu("Not doing so well uh? What you wanna do now ");
			}
			else{
				goodbyeMenu();
				return;
			}
	}
	
	public static void sendAmountMenu() throws NumberFormatException, RemoteException{
		JLabel label_destination = new JLabel("To who:");
		JTextField destination = new JTextField();
		
		JLabel label_amount = new JLabel("How much:");
		JTextField amount = new JTextField();
		
		Object[] dialogs = {label_destination,  destination, label_amount, amount};
		
		int res = JOptionPane.showConfirmDialog(null, dialogs, "Account Info", 
		        JOptionPane.CANCEL_OPTION,
		        JOptionPane.INFORMATION_MESSAGE);
		
		if(res == JOptionPane.OK_OPTION){
			String serverReply = rMIDemo.send_amount(userKey, destination.getText().trim(), Integer.parseInt(amount.getText().toString()));
			JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
			        JOptionPane.CANCEL_OPTION,
			        JOptionPane.INFORMATION_MESSAGE);
			
			mainMenu("While you wait for " +destination.getText()+" to accept, what you wanna do next?");
		}
		else{
			mainMenu("Whats up? Don't know who to send money to?");
			return;
		}
	}
	
	public static void receiveAmountMenu() throws NumberFormatException, RemoteException{
		JLabel label_id = new JLabel("Pending ID (check account, id is order):");
		JTextField id = new JTextField();
		
		Object[] dialogs = {label_id, id};
		
		int res = JOptionPane.showConfirmDialog(null, dialogs, "Account Info", 
		        JOptionPane.CANCEL_OPTION,
		        JOptionPane.INFORMATION_MESSAGE);
		if (res==0){
			String serverReply = rMIDemo.receive_ammount(userKey, Integer.parseInt(id.getText().trim()));
			res = JOptionPane.showConfirmDialog(null, serverReply, "Account Info", 
			        JOptionPane.CANCEL_OPTION,
			        JOptionPane.INFORMATION_MESSAGE);
			mainMenu("Nice, you almost rich man");
		}
		else{
			mainMenu("Forgot id? Check Account");
		}
		
		return;
	}
	
	public static void auditMenu() throws RemoteException{
		JLabel label_audit = new JLabel("Who:");
		JTextField audit = new JTextField();
		
		Object[] dialogs = {label_audit, audit};
		
		int res = JOptionPane.showConfirmDialog(null, dialogs, "Audit", 
		        JOptionPane.CANCEL_OPTION,
		        JOptionPane.INFORMATION_MESSAGE);
		if(res == 0){
			String serverReply = rMIDemo.audit(audit.getText().trim());
			JOptionPane.showConfirmDialog(null, serverReply,
				    "Auditing "+audit.getText(),
				    JOptionPane.PLAIN_MESSAGE,
				    JOptionPane.INFORMATION_MESSAGE);
		}
	}
	
	public static void goodbyeMenu(){
		JOptionPane.showConfirmDialog(null, "Thank you, " +userKey+" please come again!",
			    "Goodbye",
			    JOptionPane.PLAIN_MESSAGE,
			    JOptionPane.QUESTION_MESSAGE);
		return;
	}
}
