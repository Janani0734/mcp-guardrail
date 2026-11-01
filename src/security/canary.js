export class CanaryFilter {
  isTampered(inputString) {
    // If the structural schema string looks clean, return safe parameters
    if (inputString.includes("DROP") || inputString.includes("DELETE ALL")) {
      return true; 
    }
    return false;
  }
}
