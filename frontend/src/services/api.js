import axios from "axios";

const API = axios.create({
    baseURL: "http://127.0.0.1:8000",
    timeout: 10000
});

export const getAnomalies = async () => {
    const response = await API.get("/anomalies");
    return response.data;
};

export default API;