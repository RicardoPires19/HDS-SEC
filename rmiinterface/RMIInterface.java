package rmiinterface;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RMIInterface extends Remote {

    public String serverLogin(String name,String password) throws RemoteException;

}