import {
    FaShieldAlt,
    FaBell,
    FaBug,
    FaRobot,
    FaCog
} from "react-icons/fa";

export default function Sidebar() {

    return (

        <div className="sidebar">

            <h2>🛡 AI SOC</h2>

            <ul>

                <li><FaShieldAlt /> Dashboard</li>

                <li><FaBell /> Alerts</li>

                <li><FaBug /> MITRE</li>

                <li><FaRobot /> Investigation</li>

                <li><FaCog /> Settings</li>

            </ul>

        </div>

    );

}