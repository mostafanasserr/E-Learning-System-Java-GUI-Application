package javasemesterproject;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javasemesterproject.security.factory.DBConnectionProfile;
import javasemesterproject.security.logging.SecureLoggerFactory;

public class DBConnection {
    public Connection c;
    public Statement s;

    /** Legacy ctor – kept so existing UI code compiles unchanged. */
    public DBConnection(){
        this(DBConnectionProfile.FULL_ACCESS);
    }

    /**
     * Privilege-aware ctor used by the secure-factory pattern.
     *
     * In a real deployment, each {@link DBConnectionProfile} would map to a
     * distinct MySQL account with least-privilege GRANTs. Here we keep the
     * same JDBC URL but log the chosen profile via the SecureLogger so an
     * auditor can verify which credentials level was requested.
     */
    public DBConnection(DBConnectionProfile profile){
        SecureLoggerFactory.getInstance().getLogger().logEvent(
                "db.connect", "profile=" + profile.name() + " user=" + profile.getDbUser());
        try{
            //Register JDBC Driver with Class's Static method
            Class.forName("com.mysql.jdbc.Driver");
            c = DriverManager.getConnection("jdbc:mysql:///ELearningSystem","root","");
            s = c.createStatement();
        }
        catch(ClassNotFoundException | SQLException e){
            SecureLoggerFactory.getInstance().getLogger().logError("db.connect",
                    "JDBC connect failed for profile=" + profile.name(), e);
            System.err.println(e);
        }
    }
    public void Close(){
        try {
            c.close();
        } catch (SQLException ex) {
            Logger.getLogger(DBConnection.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
