module.exports = (sequelize, DataTypes) => {
  const Commits = sequelize.define('Commits', {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    wallet: {
      type: DataTypes.STRING(103),
      allowNull: false
    },
    link: {
      type: DataTypes.STRING(255),
      allowNull: false
    },
    date: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    },
    ip_address: {
      type: DataTypes.STRING(45),
      allowNull: false
    },
    views: {
      type: DataTypes.INTEGER,
      allowNull: false,
      defaultValue: 0
    },
    category: {
      type: DataTypes.STRING(42),
      allowNull: false,
      defaultValue: 'others'
    },
  }, {
    tableName: 'commits',
    timestamps: false
  });

  return Commits;
};
