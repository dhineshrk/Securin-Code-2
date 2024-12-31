import mongoose from "mongoose";

const connectDb = async () => {
    await mongoose.connect('mongodb://localhost:27017/sample').then(console.log("Connected"))
}
export default connectDb;