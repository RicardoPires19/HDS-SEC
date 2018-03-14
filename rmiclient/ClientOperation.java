package rmiclient;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JLabel;

import rmiinterface.RMIInterface;

public class ClientOperation {

	private static RMIInterface look_up;

	public static void main(String[] args)
		throws MalformedURLException, RemoteException, NotBoundException {

		look_up = (RMIInterface) Naming.lookup("//localhost/MyServer");

		JLabel label_login = new JLabel("Username:");
		JTextField login = new JTextField();
		 
		JLabel label_password = new JLabel("Password:");
		JPasswordField password = new JPasswordField();
		 
		Object[] array = { label_login,  login, label_password, password };
		 
		int res = JOptionPane.showConfirmDialog(null, array, "Login", 
		        JOptionPane.OK_CANCEL_OPTION,
		        JOptionPane.PLAIN_MESSAGE);


		if (res == JOptionPane.OK_OPTION) {
			String response = look_up.serverLogin(login.getText().trim(),new String(password.getPassword()));
			JOptionPane.showMessageDialog(null, response);
		}
		else{

		}

		//String response = look_up.helloTo(txt);
		

	}

}