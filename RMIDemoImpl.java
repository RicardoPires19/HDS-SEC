
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.*;

public class RMIDemoImpl extends UnicastRemoteObject implements RMIDemo{
	private static final long serialVersionUID = 1L;
	private Map<String, ArrayList<String>> ledger = new HashMap<String, ArrayList<String>>();
	private Map<String, Integer> balance = new HashMap<String,Integer>();
	private Map<String, Map<String,Integer>> pending = new HashMap<String, Map<String,Integer>>();
	
	
	protected RMIDemoImpl() throws RemoteException{
		super();
	}
	@Override
	public String doCommunicate (String name) throws RemoteException{
		System.out.println("Register: "+name);
		return "\nServer says: Hi " +name+ "\n";
	}
	@Override
	public String register(String key) throws RemoteException {
		if(ledger.containsKey(key)){
			return "Welcome back "+key+", i missed you so much! <3";
		}
		else{
			ledger.put(key, new ArrayList<String>()); //dunno how to make ledgers, doesnt matter, its just implement for the sql
			balance.put(key, 5);
			
			return "\nWelcome " + key+ ", check your account ;D";
		}
	}
	@Override
	public String send_amount(String user, String destination, int amount) throws RemoteException {
		if(balance.get(user) >= amount){
			Map<String,Integer> newsent = new HashMap<String,Integer>();
			newsent.put(user, amount);
			pending.put(destination, newsent);
			//update ledger;
			return "Sent " +amount+ " to " + destination ;
		}
		else{	
			return "Balance is insuficient, you only have " +balance.get(user)+ " BUCKS";
		}
	}
	@Override
	public String check_account(String key) throws RemoteException {
		Map<String,Integer> pending_transactions = pending.get(key);
		String serverReply = "Your balance is:\n "+ balance.get(key);;
		if(pending_transactions != null && pending_transactions.size()!=0){
			serverReply = serverReply + "\nYou have the following pending transactions:";
			for (String sender: pending_transactions.keySet()) {

				serverReply = serverReply + "\nFrom : " + sender;
				serverReply = serverReply + "\nValue : " + pending_transactions.get(sender) + "\n";	
			}
		}	
		else{
			serverReply = serverReply + "\nYou have no pending transactions";
		}
		return serverReply;
	}
	
	@Override
	public String receive_ammount(String key, int id) throws RemoteException {
		Map<String,Integer> pending_transactions = pending.get(key);
		if(pending_transactions != null && pending_transactions.size()!=0){
			if (pending_transactions.size() >= id) {
				String sender = (String) new ArrayList(pending_transactions.keySet()).get(id-1);
				//UPDATE LEDGER;
				int transaction_value = pending_transactions.get(sender);
				balance.put(key, balance.get(key) + transaction_value);
				System.out.println("new balance " + key +": " + balance.get(key));
				pending_transactions.remove(sender);
				pending.put(key, pending_transactions);
				return "Gratz you just received " + transaction_value + " from " + sender;
			}
			else{
				return "Not valid id, check account again";
			}
		}
		else{
			return "Sorry but you have no pending transactions T^T";
		}
	}
	@Override
	public String audit(String key) throws RemoteException {
		// TODO Auto-generated method stub
		//PRINT LEDGERS
		return null;
	}
}
