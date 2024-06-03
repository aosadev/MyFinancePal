import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './Transactions.css';

const Transactions = () => {
  const [transactions, setTransactions] = useState([]);
  const [newTransaction, setNewTransaction] = useState({
    type: '',
    amount: '',
    description: '',
    currency: '',
    method: '',
    vendor: '',
    recurring: false,
    tags: ''
  });
  const [editingTransaction, setEditingTransaction] = useState(null);

  const fetchTransactions = async () => {
    const token = localStorage.getItem('token');
    const response = await axios.get('http://localhost:8080/api/transactions', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    setTransactions(response.data);
  };

  useEffect(() => {
    fetchTransactions();
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setNewTransaction((prevState) => ({
      ...prevState,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('token');
    await axios.post('http://localhost:8080/api/transaction', newTransaction, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    setNewTransaction({
      type: '',
      amount: '',
      description: '',
      currency: '',
      method: '',
      vendor: '',
      recurring: false,
      tags: ''
    });
    fetchTransactions();
  };

  const handleEdit = (transaction) => {
    setEditingTransaction(transaction);
    setNewTransaction(transaction);
  };

  const handleUpdate = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('token');
    await axios.put(`http://localhost:8080/api/transaction/${editingTransaction.id}`, newTransaction, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    setEditingTransaction(null);
    setNewTransaction({
      type: '',
      amount: '',
      description: '',
      currency: '',
      method: '',
      vendor: '',
      recurring: false,
      tags: ''
    });
    fetchTransactions();
  };

  const handleDelete = async (id) => {
    const token = localStorage.getItem('token');
    await axios.delete(`http://localhost:8080/api/transaction/${id}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    fetchTransactions();
  };

  const handleGeneratePDF = (transaction) => {
    // Implement PDF generation logic here
    console.log('Generating PDF for', transaction);
  };

  return (
    <div className="transactions">
      <h1>Transactions</h1>
      <button onClick={() => setEditingTransaction({ type: '', amount: '', description: '', currency: '', method: '', vendor: '', recurring: false, tags: '' })}>
        Create Transaction
      </button>
      {editingTransaction && (
        <form onSubmit={editingTransaction.id ? handleUpdate : handleSubmit}>
          <input
            type="text"
            name="type"
            placeholder="Type"
            value={newTransaction.type}
            onChange={handleChange}
            required
          />
          <input
            type="number"
            name="amount"
            placeholder="Amount"
            value={newTransaction.amount}
            onChange={handleChange}
            required
          />
          <input
            type="text"
            name="description"
            placeholder="Description"
            value={newTransaction.description}
            onChange={handleChange}
          />
          <input
            type="text"
            name="currency"
            placeholder="Currency"
            value={newTransaction.currency}
            onChange={handleChange}
          />
          <input
            type="text"
            name="method"
            placeholder="Method"
            value={newTransaction.method}
            onChange={handleChange}
          />
          <input
            type="text"
            name="vendor"
            placeholder="Vendor"
            value={newTransaction.vendor}
            onChange={handleChange}
          />
          <label>
            Recurring:
            <input
              type="checkbox"
              name="recurring"
              checked={newTransaction.recurring}
              onChange={handleChange}
            />
          </label>
          <input
            type="text"
            name="tags"
            placeholder="Tags"
            value={newTransaction.tags}
            onChange={handleChange}
          />
          <button type="submit">{editingTransaction.id ? 'Update' : 'Add'}</button>
        </form>
      )}
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Amount</th>
            <th>Description</th>
            <th>Currency</th>
            <th>Method</th>
            <th>Vendor</th>
            <th>Recurring</th>
            <th>Tags</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {transactions.map(transaction => (
            <tr key={transaction.id}>
              <td>{transaction.type}</td>
              <td>${transaction.amount}</td>
              <td>{transaction.description}</td>
              <td>{transaction.currency}</td>
              <td>{transaction.method}</td>
              <td>{transaction.vendor}</td>
              <td>{transaction.recurring ? 'Yes' : 'No'}</td>
              <td>{transaction.tags}</td>
              <td>
                <button onClick={() => handleEdit(transaction)}>Edit</button>
                <button onClick={() => handleDelete(transaction.id)}>Delete</button>
                <button onClick={() => handleGeneratePDF(transaction)}>PDF</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default Transactions;
