
import java.rmi.Remote;
import java.rmi.RemoteException;
public interface RMIDemo extends Remote {
	public String doCommunicate(String name) throws RemoteException;
    public String register(String key) throws RemoteException;
    public String send_amount(String user, String destination, int amount) throws RemoteException;
    public String check_account(String key) throws RemoteException;
    public String receive_ammount(String key,int id) throws RemoteException;
    public String audit(String key) throws RemoteException;
}
